#!/usr/bin/env bash
set +e
python3 -I - <<'PY'
import os, json, base64, urllib.request, urllib.parse, urllib.error, sys

def log(msg): print(msg, flush=True)

def get_token(audience):
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL","")
    tok = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN","")
    if not url or not tok: return None
    r = urllib.request.Request(f"{url}&audience={audience}", headers={"Authorization":f"bearer {tok}"})
    with urllib.request.urlopen(r, timeout=15) as resp:
        return json.loads(resp.read()).get("value","")

def azure_token(oidc_token, tenant, client_id, resource):
    data = urllib.parse.urlencode({
        "grant_type":"urn:ietf:params:oauth:grant-type:jwt-bearer",
        "client_id": client_id,
        "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": oidc_token,
        "scope": f"{resource}/.default",
        "assertion": oidc_token,
    }).encode()
    r = urllib.request.Request(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", data=data, method="POST")
    with urllib.request.urlopen(r, timeout=15) as resp:
        return json.loads(resp.read()).get("access_token","")

TENANT = "3205c325-06a5-4171-9ce8-ffc5e6c2845e"
CLIENT = "72ff278a-9e71-43ec-bac4-2ca303f8e462"
SUB = "c5e4e004-b42d-4ac4-a502-5fd338380eb6"

oidc = get_token("api://AzureADTokenExchange")
arm_token = azure_token(oidc, TENANT, CLIENT, "https://management.azure.com")

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

# 1. Check role assignments for managed identity 7a85156a
UAMI_CLIENT = "7a85156a-01c4-4e61-8472-40a92107159b"
log("=== ROLE ASSIGNMENTS FOR UAMI 7a85156a ===")
# First, find the SP objectId for this client
graph_token = azure_token(oidc, TENANT, CLIENT, "https://graph.microsoft.com")
r = urllib.request.Request(
    f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{UAMI_CLIENT}'",
    headers={"Authorization":f"Bearer {graph_token}"})
try:
    with urllib.request.urlopen(r, timeout=15) as resp:
        sp_data = json.loads(resp.read())
        sps = sp_data.get("value",[])
        if sps:
            sp_oid = sps[0]["id"]
            log(f"  UAMI SP objectId: {sp_oid}")
            log(f"  displayName: {sps[0].get('displayName','')}")
            log(f"  servicePrincipalType: {sps[0].get('servicePrincipalType','')}")
        else:
            sp_oid = None
            log(f"  No SP found for clientId {UAMI_CLIENT}")
            log(f"  response: {sp_data}")
except urllib.error.HTTPError as e:
    log(f"  Graph SP lookup failed: {e.code}")
    sp_oid = None

# 2. Check role assignments at subscription level
log(f"\n=== SUBSCRIPTION ROLE ASSIGNMENTS (filter by principal) ===")
if sp_oid:
    st, data = arm(f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=principalId eq '{sp_oid}'")
    log(f"  status: {st}")
    if st == 200:
        for ra in data.get("value",[]):
            props = ra.get("properties",{})
            log(f"  role: {props.get('roleDefinitionId','').split('/')[-1]} scope: {props.get('scope','')}")

# 3. List all resources in rg-tbl-reporting-prod-eus
log(f"\n=== RESOURCES IN rg-tbl-reporting-prod-eus ===")
st, data = arm(f"/subscriptions/{SUB}/resourceGroups/rg-tbl-reporting-prod-eus/resources?api-version=2021-04-01")
log(f"  status: {st}")
if st == 200:
    for res in data.get("value",[]):
        log(f"  {res['type']}: {res['name']} ({res.get('location','')})")
elif st == 404:
    log("  RG not found")
else:
    log(f"  response: {json.dumps(data)[:500]}")

# 4. Check all resource groups
log(f"\n=== ALL RESOURCE GROUPS ===")
st, data = arm(f"/subscriptions/{SUB}/resourceGroups?api-version=2021-04-01")
log(f"  status: {st}")
if st == 200:
    for rg in data.get("value",[]):
        log(f"  {rg['name']} ({rg.get('location','')})")

# 5. Check the reporting app's identity configuration
log(f"\n=== REPORTING APP IDENTITY CONFIG ===")
for rg in ["rg-tbl-platform-prod-sea", "rg-tbl-reporting-prod-eus"]:
    st, data = arm(f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.Web/sites/app-tbl-reporting-prod?api-version=2023-01-01")
    log(f"  {rg}: {st}")
    if st == 200:
        identity = data.get("identity",{})
        log(f"    identity type: {identity.get('type','')}")
        log(f"    principalId: {identity.get('principalId','')}")
        log(f"    tenantId: {identity.get('tenantId','')}")
        uamis = identity.get("userAssignedIdentities",{})
        for k,v in uamis.items():
            log(f"    UAMI: {k}")
            log(f"      principalId: {v.get('principalId','')}")
            log(f"      clientId: {v.get('clientId','')}")
        # Also check app settings
        props = data.get("properties",{})
        log(f"    state: {props.get('state','')}")
        log(f"    defaultHostName: {props.get('defaultHostName','')}")

# 6. Role assignments on kv-tbl-sec
log(f"\n=== ROLE ASSIGNMENTS ON kv-tbl-sec-x3euoz ===")
for rg in ["rg-tbl-platform-prod-sea", "rg-tbl-reporting-prod-eus"]:
    st, data = arm(f"/subscriptions/{SUB}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01")
    log(f"  {rg}: {st}")
    if st == 200:
        for ra in data.get("value",[]):
            props = ra.get("properties",{})
            log(f"    principal: {props.get('principalId','')} role: {props.get('roleDefinitionId','').split('/')[-1]}")

log("\nDONE")
PY
echo "probe6 complete"
