#!/usr/bin/env bash
set +e
python3 -I - <<'PY'
import os, json, base64, urllib.request, urllib.parse, urllib.error, sys

def log(msg): print(msg, flush=True)

def get_token(audience):
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL","")
    tok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN","")
    r = urllib.request.Request(f"{url}&audience={audience}", headers={"Authorization":f"bearer {tok}"})
    with urllib.request.urlopen(r, timeout=15) as resp:
        return json.loads(resp.read()).get("value","")

def azure_token(oidc_token, tenant, client_id, resource):
    data = urllib.parse.urlencode({
        "grant_type":"client_credentials",
        "client_id": client_id,
        "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": oidc_token,
        "scope": f"{resource}/.default",
    }).encode()
    r = urllib.request.Request(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", data=data, method="POST")
    with urllib.request.urlopen(r, timeout=15) as resp:
        return json.loads(resp.read()).get("access_token","")

TENANT = "3205c325-06a5-4171-9ce8-ffc5e6c2845e"
CLIENT = "72ff278a-9e71-43ec-bac4-2ca303f8e462"
SUB = "c5e4e004-b42d-4ac4-a502-5fd338380eb6"
UAMI_CLIENT = "7a85156a-01c4-4e61-8472-40a92107159b"

try:
    oidc = get_token("api://AzureADTokenExchange")
    log(f"OIDC token length: {len(oidc)}")
except Exception as e:
    log(f"OIDC failed: {e}")
    sys.exit(1)

try:
    arm_token = azure_token(oidc, TENANT, CLIENT, "https://management.azure.com")
    log(f"ARM token length: {len(arm_token)}")
except Exception as e:
    log(f"ARM token failed: {e}")
    sys.exit(1)

try:
    graph_token = azure_token(oidc, TENANT, CLIENT, "https://graph.microsoft.com")
    log(f"Graph token length: {len(graph_token)}")
except Exception as e:
    log(f"Graph token failed: {e}")
    graph_token = None

def arm(path, method="GET"):
    url = f"https://management.azure.com{path}"
    r = urllib.request.Request(url, headers={"Authorization":f"Bearer {arm_token}"}, method=method)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode())
        except: return e.code, {}
    except Exception as e: return 0, str(e)

def graph(path):
    r = urllib.request.Request(f"https://graph.microsoft.com/v1.0{path}",
                               headers={"Authorization":f"Bearer {graph_token}"})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode())
        except: return e.code, {}
    except Exception as e: return 0, str(e)

# 1. Look up UAMI SP
log("\n=== UAMI SP LOOKUP ===")
if graph_token:
    st, data = graph(f"/servicePrincipals?$filter=appId eq '{UAMI_CLIENT}'")
    log(f"  status: {st}")
    sp_oid = None
    if st == 200:
        sps = data.get("value",[])
        for sp in sps:
            sp_oid = sp["id"]
            log(f"  objectId: {sp_oid}")
            log(f"  displayName: {sp.get('displayName','')}")
            log(f"  type: {sp.get('servicePrincipalType','')}")
    else:
        log(f"  response: {json.dumps(data)[:300]}")

# 2. Role assignments for UAMI
if sp_oid:
    log("\n=== ROLE ASSIGNMENTS FOR UAMI ===")
    st, data = arm(f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=principalId eq '{sp_oid}'")
    log(f"  status: {st}")
    if st == 200:
        ras = data.get("value",[])
        log(f"  count: {len(ras)}")
        for ra in ras:
            props = ra.get("properties",{})
            rid = props.get("roleDefinitionId","").split("/")[-1]
            log(f"  role: {rid} scope: {props.get('scope','')}")
    else:
        log(f"  response: {json.dumps(data)[:300]}")

# 3. All resource groups
log("\n=== ALL RESOURCE GROUPS ===")
st, data = arm(f"/subscriptions/{SUB}/resourceGroups?api-version=2021-04-01")
log(f"  status: {st}")
if st == 200:
    for rg in data.get("value",[]):
        log(f"  {rg['name']} ({rg.get('location','')})")

# 4. Reporting app identity
log("\n=== REPORTING APP IDENTITY ===")
for rg in ["rg-tbl-platform-prod-sea", "rg-tbl-reporting-prod-eus"]:
    st, data = arm(f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Web/sites/app-tbl-reporting-prod?api-version=2023-01-01")
    if st == 200:
        log(f"  Found in {rg}")
        identity = data.get("identity",{})
        log(f"  identity type: {identity.get('type','')}")
        log(f"  principalId: {identity.get('principalId','')}")
        uamis = identity.get("userAssignedIdentities",{})
        for k,v in uamis.items():
            log(f"  UAMI: {k}")
            log(f"    principalId: {v.get('principalId','')}")
            log(f"    clientId: {v.get('clientId','')}")
        props = data.get("properties",{})
        log(f"  state: {props.get('state','')}")
        log(f"  siteConfig startup: {props.get('siteConfig',{}).get('appCommandLine','')}")

# 5. KV-sec RBAC
log("\n=== KV-TBL-SEC ROLE ASSIGNMENTS ===")
for rg in ["rg-tbl-platform-prod-sea"]:
    st, data = arm(f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01")
    log(f"  {rg}: {st}")
    if st == 200:
        for ra in data.get("value",[]):
            props = ra.get("properties",{})
            pid = props.get("principalId","")
            rid = props.get("roleDefinitionId","").split("/")[-1]
            log(f"    principal={pid} role={rid}")
            # Look up role definition name
            rdst, rddata = arm(props.get("roleDefinitionId","") + "?api-version=2022-04-01")
            if rdst == 200:
                rname = rddata.get("properties",{}).get("roleName","")
                log(f"      roleName: {rname}")

# 6. Resources in rg-tbl-reporting-prod-eus (if exists)
log("\n=== RESOURCES IN rg-tbl-reporting-prod-eus ===")
st, data = arm(f"/subscriptions/{SUB}/resourceGroups/rg-tbl-reporting-prod-eus/resources?api-version=2021-04-01")
log(f"  status: {st}")
if st == 200:
    for res in data.get("value",[]):
        log(f"  {res['type']}: {res['name']} ({res.get('location','')})")

# 7. Resources in ALL RGs
log("\n=== ALL SUBSCRIPTION RESOURCES ===")
st, data = arm(f"/subscriptions/{SUB}/resources?api-version=2021-04-01")
log(f"  status: {st}")
if st == 200:
    for res in data.get("value",[]):
        log(f"  {res['type']}: {res['name']} (rg={res.get('id','').split('/')[4] if len(res.get('id','').split('/'))>4 else '?'})")

log("\nDONE")
PY
echo "probe7 complete"
