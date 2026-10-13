#!/usr/bin/env python3
"""Verify exported service clients in a disposable exact-image Keycloak (synthetic only).
Secrets/tokens remain in memory and never enter logs. Requires Docker and Python.
"""
import argparse
import base64
import concurrent.futures
import json
from pathlib import Path
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def main(image):
    name = 'backend-client-probe-' + uuid.uuid4().hex[:12]
    checks = []
    admin_password = 'Synthetic-master-password-2026!'
    def docker(*args):
        return subprocess.check_output(['docker', *args], stderr=subprocess.PIPE).decode().strip()
    def check(label, actual, expected):
        checks.append({'test':label,'actual':actual,'expected':expected})
        if actual != expected:
            raise AssertionError(f'{label}: expected {expected!r}, got {actual!r}')
    try:
        docker('run','-d','--platform','linux/amd64','--name',name,'-p','127.0.0.1::8080',
               '-e','KC_BOOTSTRAP_ADMIN_USERNAME=probe-admin','-e','KC_BOOTSTRAP_ADMIN_PASSWORD='+admin_password,
               '-e','ORISO_APP_BASE_URL=http://localhost','-e','EMAIL_BRANDING_NAME=Synthetic',
               '-e','EMAIL_LEGAL_ORGANISATION_NAME=Synthetic',image,'start-dev','--db=dev-file','--http-relative-path=/auth')
        base='http://127.0.0.1:'+docker('port',name,'8080/tcp').split(':')[-1]+'/auth'
        def request(path,data=None,token=None,method=None):
            headers={}
            if isinstance(data,dict):
                data=json.dumps(data).encode();headers['Content-Type']='application/json'
            if token:headers['Authorization']='Bearer '+token
            try:
                with urllib.request.urlopen(urllib.request.Request(base+path,data,headers,method=method),timeout=30) as res:
                    raw=res.read();return res.status,json.loads(raw) if raw else None
            except urllib.error.HTTPError as err:
                raw=err.read();return err.code,json.loads(raw) if raw else None
        def grant(realm,form):
            return request('/realms/'+realm+'/protocol/openid-connect/token',urllib.parse.urlencode(form).encode())
        def master():
            return grant('master',{'grant_type':'password','client_id':'admin-cli','username':'probe-admin','password':admin_password})
        for _ in range(900):
            try:
                status,body=master()
                if status==200:break
            except (OSError,urllib.error.URLError):pass
            if docker('inspect','--format','{{.State.Status}}',name)=='exited':
                raise AssertionError('isolated server exited during startup')
            time.sleep(1)
        else:raise AssertionError('isolated server startup timeout')
        mt=body['access_token'];realm='backend-service-probe'
        exported=json.loads((Path(__file__).resolve().parents[1]/'realm.json').read_text())
        client_ids=('backend-technical','backend-admin')
        source={'realm':realm,'enabled':True,'bruteForceProtected':True,
                'permanentLockout':exported['permanentLockout'],'maxTemporaryLockouts':exported['maxTemporaryLockouts'],
                'maxSecondaryAuthFailures':exported.get('maxSecondaryAuthFailures',0),'failureFactor':exported['failureFactor'],
                'bruteForceStrategy':exported['bruteForceStrategy'],'waitIncrementSeconds':exported['waitIncrementSeconds'],
                'maxFailureWaitSeconds':exported['maxFailureWaitSeconds'],'maxDeltaTimeSeconds':exported['maxDeltaTimeSeconds'],
                'quickLoginCheckMilliSeconds':exported['quickLoginCheckMilliSeconds'],
                'minimumQuickLoginWaitSeconds':exported['minimumQuickLoginWaitSeconds'],
                'roles':{'realm':[r for r in exported['roles']['realm'] if r['name'] in ('technical','otp-config-admin')]},
                'clients':[c for c in exported['clients'] if c['clientId'] in client_ids],
                'scopeMappings':[m for m in exported['scopeMappings'] if m.get('client') in client_ids],
                'clientScopeMappings':{'realm-management':exported['clientScopeMappings']['realm-management']},
                'users':[u for u in exported['users'] if u.get('serviceAccountClientId') in client_ids]}
        source['users'].append({'username':'legacy-password','enabled':True,'credentials':[{'type':'password','value':'Synthetic-user-password-2026!'}]})
        source['clients'].append({'clientId':'app','enabled':True,'publicClient':True,'directAccessGrantsEnabled':True})
        source['clients'].append({'clientId':'legacy-password-probe','enabled':True,'publicClient':True,'directAccessGrantsEnabled':True})
        import_status,import_body=request('/admin/realms',source,mt)
        if import_status!=201:
            message=import_body.get('errorMessage') if isinstance(import_body,dict) else None
            raise AssertionError('isolated export import failed: '+str(import_status)+' '+str(message or 'no safe detail'))
        check('isolated-export-import',import_status,201)
        def admin(path):
            nonlocal mt
            status,body=request('/admin/realms/'+realm+path,token=mt)
            if status==401:
                mt=master()[1]['access_token'];return admin(path)
            return status,body
        secrets={};tokens={}
        expected={
            'backend-technical':('12316d09-a9da-41b9-a13e-ee2c515800b5',['technical'],{}),
            'backend-admin':('615a7bf8-3e12-40c7-a949-f88640acea8e',['otp-config-admin'],{'realm-management':['manage-users','query-groups','query-users','view-realm','view-users']}),
        }
        for client,(subject,roles,client_roles) in expected.items():
            ci=admin('/clients?clientId='+client)[1][0]['id']
            secret=admin('/clients/'+ci+'/client-secret')[1]['value'];secrets[client]=secret
            check(client+'-random-import-secret',bool(secret) and len(secret)>=20 and not secret.startswith('${'),True)
            check(client+'-exported-subject',admin('/clients/'+ci+'/service-account-user')[1]['id'],subject)
            status,body=grant(realm,{'grant_type':'client_credentials','client_id':client,'client_secret':secret})
            check(client+'-client-credentials',status,200);tokens[client]=body['access_token']
            payload=body['access_token'].split('.')[1]
            claims=json.loads(base64.urlsafe_b64decode(payload+'='*(-len(payload)%4)))
            check(client+'-subject-client', [claims['sub'],claims['azp']], [subject,client])
            check(client+'-exact-realm-roles',sorted(claims.get('realm_access',{}).get('roles',[])),sorted(roles))
            actual={k:sorted(v['roles']) for k,v in claims.get('resource_access',{}).items()}
            check(client+'-exact-resource-roles',actual,client_roles)
            check(client+'-password-grant-disabled',grant(realm,{'grant_type':'password','client_id':client,'client_secret':secret,'username':'legacy-password','password':'Synthetic-user-password-2026!'})[0],400)
        check('independent-client-secrets',secrets['backend-technical']!=secrets['backend-admin'],True)
        check('technical-cannot-read-users',request('/admin/realms/'+realm+'/users',token=tokens['backend-technical'])[0],403)
        check('admin-can-read-users',request('/admin/realms/'+realm+'/users',token=tokens['backend-admin'])[0],200)
        check('admin-can-read-realm',request('/admin/realms/'+realm,token=tokens['backend-admin'])[0],200)
        check('admin-cannot-list-clients',request('/admin/realms/'+realm+'/clients',token=tokens['backend-admin'])[0],403)
        check('admin-cannot-update-realm',request('/admin/realms/'+realm,{},tokens['backend-admin'],'PUT')[0],403)
        for client,secret in secrets.items():
            barrier=threading.Barrier(20)
            def parallel_client_credentials(_):
                barrier.wait()
                return grant(realm,{'grant_type':'client_credentials','client_id':client,'client_secret':secret})[0]
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
                statuses=list(pool.map(parallel_client_credentials,range(20)))
            check(client+'-20-parallel-client-credentials',statuses,[200]*20)
        requested_subject=admin('/users?username=legacy-password')[1][0]['id']
        def exchange(token):
            return grant(realm,{'grant_type':'urn:ietf:params:oauth:grant-type:token-exchange','client_id':'app','subject_token':token,'requested_subject':requested_subject})
        migrated_exchange=exchange(tokens['backend-admin'])
        check('requested-subject-exchange-remains-unsupported',migrated_exchange[0] in (400,403),True)
        checks.append({'test':'existing-exchange-limitation','serviceClient':migrated_exchange[1]})
        for _ in range(15):
            time.sleep(1.05)
            check('legacy-bad-password-refused',grant(realm,{'grant_type':'password','client_id':'legacy-password-probe','username':'legacy-password','password':'incorrect-synthetic'})[0],400)
        uid=admin('/users?username=legacy-password')[1][0]['id']
        check('legacy-user-locked',admin('/attack-detection/brute-force/users/'+uid)[1]['disabled'],True)
        for client,secret in secrets.items():
            check(client+'-works-during-legacy-lock',grant(realm,{'grant_type':'client_credentials','client_id':client,'client_secret':secret})[0],200)
        print(json.dumps({'image':image,'checks':checks},indent=2))
    finally:
        subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',required=True)
    main(p.parse_args().image)
