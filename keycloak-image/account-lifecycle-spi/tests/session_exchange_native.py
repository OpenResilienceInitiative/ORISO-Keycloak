#!/usr/bin/env python3
"""One finite native SPI tracer; actor/claim are fixture inputs, not final User authority proof."""
import base64
import copy
from collections import Counter
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
import struct
from concurrent.futures import ThreadPoolExecutor
import threading
import unittest
from urllib.parse import quote
import uuid
import lifecycle_fixture as native
from maintenance_human_fixture import HumanMaintenanceFixture

OBSERVATIONS = {
    "fixtureClaimOnly": True, "fiveActorsExact": False, "adminNoDirectGrant": False,
    "adminCannotQueryUsers": False, "ordinaryPasswordLogin": False,
    "sourceOtpExecutionsPreserved": False, "nativeRouterSelected": False,
    "commandMacValid": False, "nativeVersionPinned": False, "magicStatus": 0,
}


SESSION_CHECKS = dict.fromkeys(("nativeSubjectClientTenantExpiry","actualNativeSessionBound",
    "sameWorkflowSameSession","changedTupleRefused","unboundBodyRefused","wrongActorRefused",
    "wrongProofAudienceRefused","expiredCommandRefused","currentDisabledRefused",
    "requiredActionRefused","concurrentSameWorkflowOneSession","mfaMissingWrongAndCorrect",
    "mfaReplayRequiresNewValidCode","lateRequiredActionNoOrphan"),False)


TOKEN_FACTS = dict.fromkeys(("subjectPresent","subjectMatchesTarget","subjectMatchesCanonicalAdmin",
    "clientMatchesApp","tenantPresent","tenantMatchesTarget","sessionIdPresent"),False)


def proof(body, realm_id, claim_changes=None):
    now = int(time.time())
    claims = {
        "iss": "userservice", "aud": "oriso-session-exchange", "purpose": "SESSION_EXCHANGE",
        "operation": "session.magic-link.exchange", "method": "POST", "actor": "ACCOUNT_ADMIN",
        "realm": native.REALM,
        "target": "realm/" + realm_id + "/magic-link/" + body["workflowId"],
        "taskClient": "backend-account-admin", "taskSubject": native.SUBJECTS["ACCOUNT_ADMIN"],
        "payloadDigest": native.mac("magic-link-command/v1", body),
        "jti": str(uuid.uuid4()), "nonce": uuid.uuid4().hex, "iat": now, "exp": now + 30,
    }
    claims.update(claim_changes or {})
    encoded = base64.urlsafe_b64encode(native.canonical(claims)).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(hmac.new(
        native.CONTEXT_KEY, ("magic-link-proof/v1\n" + encoded).encode(), hashlib.sha256
    ).digest()).decode().rstrip("=")
    return encoded + "." + signature


class SessionExchangeNative(native.LifecycleFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Strict outer driver owns all Docker resources and the finite readiness deadline.
        cls.base = os.environ["S1_NATIVE_BASE"]
        cls.installer = os.environ["S1_INSTALLER_BEARER"]

    def setUp(self):
        source = json.loads((Path(__file__).resolve().parents[3] / "realm.json").read_text())
        self.source_app = next(client for client in source["clients"] if client["clientId"] == "app")
        source_scope_names = set(self.source_app["defaultClientScopes"]+self.source_app["optionalClientScopes"])
        source_scopes = [scope for scope in source["clientScopes"] if scope["name"] in source_scope_names]
        self.assertEqual(source_scope_names,{scope["name"] for scope in source_scopes})
        aliases = {"direct-grant-2fa"}
        flows = source["authenticationFlows"]
        changed = True
        while changed:
            changed = False
            for flow in flows:
                if flow["alias"] in aliases:
                    for step in flow.get("authenticationExecutions", []):
                        alias = step.get("flowAlias")
                        if alias and alias not in aliases:
                            aliases.add(alias)
                            changed = True
        selected = [flow for flow in flows if flow["alias"] in aliases]
        self.assertEqual(aliases, {flow["alias"] for flow in selected})
        self.assertTrue(any(step.get("authenticator") == "email-authenticator"
                            for flow in selected for step in flow.get("authenticationExecutions", [])))
        self.assertTrue(any(step.get("authenticator") == "direct-grant-validate-otp"
                            for flow in selected for step in flow.get("authenticationExecutions", [])))
        original = native.call
        imported = []
        def import_only(base, method, path, body=None, token=None, form=False, proof=None):
            if method == "POST" and path == "/admin/realms":
                self.assertFalse(imported)
                imported.append(True)
                wired = copy.deepcopy(selected)
                direct = next(flow for flow in wired if flow["alias"] == "direct-grant-2fa")
                credentials = [step for step in direct["authenticationExecutions"]
                               if step.get("authenticator") in {"direct-grant-validate-username","direct-grant-validate-password"}]
                self.assertEqual(2,len(credentials))
                direct["authenticationExecutions"] = [
                    {"authenticator":"oriso-claimed-magic-link","authenticatorFlow":False,"requirement":"REQUIRED","priority":0},
                    {"flowAlias":"oriso-ordinary-password","authenticatorFlow":True,"requirement":"CONDITIONAL","priority":10},
                    *[step for step in direct["authenticationExecutions"] if step not in credentials],
                    {"authenticator":"oriso-claimed-magic-link-attach","authenticatorFlow":False,"requirement":"REQUIRED","priority":50},
                ]
                wired.append({"alias":"oriso-ordinary-password","providerId":"basic-flow","topLevel":False,"builtIn":False,
                              "authenticationExecutions":[
                                  {"authenticator":"oriso-magic-link-ordinary-password","authenticatorFlow":False,"requirement":"REQUIRED","priority":0},
                                  *credentials]})
                body = {**body, "clientScopes": source_scopes, "authenticationFlows": wired,
                        "authenticatorConfig": source.get("authenticatorConfig", []),
                        "directGrantFlow": "direct-grant-2fa"}
            return original(base, method, path, body, token, form, proof)
        native.call = import_only
        try:
            super().setUp()
        finally:
            native.call = original
        self.assertEqual([True], imported)
        self.expected_executions = Counter((step["authenticator"], step["requirement"])
            for flow in selected for step in flow.get("authenticationExecutions", [])
            if step.get("authenticator"))
        actual = self.admin("GET", "/authentication/flows/direct-grant-2fa/executions")
        self.magic_providers = {"oriso-claimed-magic-link","oriso-claimed-magic-link-attach","oriso-magic-link-ordinary-password"}
        self.assertEqual(self.expected_executions, Counter((step["providerId"],step["requirement"])
            for step in actual if step.get("providerId") and not step.get("authenticationFlow")
            and step["providerId"] not in self.magic_providers))
        self.assertEqual("oriso-claimed-magic-link",actual[0]["providerId"])
        self.assertEqual("oriso-claimed-magic-link-attach",actual[-1]["providerId"])
        self.assertEqual(self.magic_providers,{step.get("providerId") for step in actual}&self.magic_providers)
        OBSERVATIONS["sourceOtpExecutionsPreserved"] = True

    def test_checked_claim_enters_native_session_path(self):
        status, server = native.call(self.base, "GET", "/admin/serverinfo", token=self.installer)
        self.assertEqual(200,status)
        self.assertEqual("26.6.3",server["systemInfo"]["version"])
        OBSERVATIONS["nativeVersionPinned"] = True
        self.assertEqual(5, len(native.ACTORS))
        OBSERVATIONS["fiveActorsExact"] = True
        admin_client = self.admin("GET", "/clients/" + self.client_ids["ACCOUNT_ADMIN"])
        self.assertIs(False, admin_client["directAccessGrantsEnabled"])
        OBSERVATIONS["adminNoDirectGrant"] = True
        actor = self.token("ACCOUNT_ADMIN")
        status, _ = native.call(self.base, "GET", "/admin/realms/" + native.REALM + "/users", token=actor)
        self.assertEqual(403, status)
        OBSERVATIONS["adminCannotQueryUsers"] = True
        # Authentication-relevant app configuration comes from the exact current realm source.
        app_fields = ("clientId","enabled","publicClient","standardFlowEnabled",
                      "directAccessGrantsEnabled","serviceAccountsEnabled","fullScopeAllowed",
                      "defaultClientScopes","optionalClientScopes","protocol","consentRequired",
                      "authenticationFlowBindingOverrides","attributes")
        app = {key:self.source_app[key] for key in app_fields}
        self.admin("POST", "/clients", app)
        current_app = self.admin("GET", "/clients?clientId=app")[0]
        for field in app_fields:
            expected,actual = app[field],current_app[field]
            if field == "attributes":
                # Native derived metadata is not an app authentication setting.
                actual = {key:actual.get(key) for key in expected}
            if field in {"defaultClientScopes","optionalClientScopes"}:
                expected,actual = set(expected),set(actual)
            self.assertEqual(expected,actual)
        # This setup matches HumanMaintenanceFixture's proven managed-profile preparation.
        profile = self.admin("GET", "/users/profile")
        tenant_attribute = {
            "name": "tenantId", "multivalued": False,
            "permissions": {"view": ["admin", "user"], "edit": ["admin"]},
            "validations": {"pattern": {"pattern": "0|[1-9][0-9]{0,18}"}},
        }
        self.assertFalse(any(item["name"] == "tenantId" for item in profile["attributes"]))
        profile["attributes"].append(tenant_attribute)
        if not any(item["name"] == "locale" for item in profile["attributes"]):
            profile["attributes"].append({
                "name": "locale", "multivalued": False,
                "permissions": {"view": ["admin", "user"], "edit": ["admin", "user"]},
                "validations": {"pattern": {"pattern": "de|fr|it"}},
            })
        self.admin("PUT", "/users/profile", profile)
        current_profile = self.admin("GET", "/users/profile")
        current_tenant = [item for item in current_profile["attributes"] if item["name"] == "tenantId"]
        self.assertEqual(1,len(current_tenant))
        for field,value in tenant_attribute.items():
            self.assertEqual(value,current_tenant[0][field])
        # Reuse the already-GREEN native create/commit helpers, not an ad hoc admin-created user.
        human_profile = HumanMaintenanceFixture.reviewed_human_profile()
        attempt,creation = str(uuid.uuid4()),self.creation(kind=human_profile["kind"],group=human_profile["group"])
        status,opened = self.request("create",attempt,creation)
        self.assertEqual(201,status)
        status,committed = self.request("commit",attempt,self.finish(creation,opened))
        self.assertEqual(200,status)
        self.assertEqual("COMMITTED",committed["state"])
        target = self.admin("GET", "/users/"+opened["accountId"])
        account = creation["account"]
        for field in ("username","email","firstName","lastName"):
            self.assertEqual(account[field],target[field])
        self.assertTrue(target["enabled"])
        self.assertIsNone(target.get("serviceAccountClientLink"))
        self.assertFalse(target.get("requiredActions"))
        self.assertEqual([creation["identity"]["scope"]["tenantId"]],target["attributes"]["tenantId"])
        current_roles = self.admin("GET", "/users/"+target["id"]+"/role-mappings/realm/composite")
        self.assertEqual(set(human_profile["roles"]),{role["name"] for role in current_roles})
        groups = self.admin("GET", "/users/"+target["id"]+"/groups")
        self.assertEqual({self.group_id("/human-roles/"+human_profile["group"])},{group["id"] for group in groups})
        username,password = account["username"],account["password"]
        token_path = "/realms/" + native.REALM + "/protocol/openid-connect/token"
        status, ordinary = native.call(self.base, "POST", token_path, {
            "client_id": "app", "grant_type": "password", "username": username,
            "password": password}, form=True)
        self.assertEqual(200, status)
        self.assertTrue(ordinary.get("access_token"))
        OBSERVATIONS["ordinaryPasswordLogin"] = True
        status,_ = native.call(self.base,"POST","/admin/realms/"+native.REALM+
                               "/users/"+target["id"]+"/logout",token=self.installer)
        self.assertEqual(204,status)
        self.assertEqual([],self.admin("GET","/users/"+target["id"]+"/sessions"))
        steps = self.admin("GET", "/authentication/flows/direct-grant-2fa/executions")
        self.assertEqual("oriso-claimed-magic-link", steps[0]["providerId"])
        self.assertEqual("oriso-claimed-magic-link-attach", steps[-1]["providerId"])
        self.assertEqual(self.expected_executions, Counter((step["providerId"],step["requirement"])
            for step in steps if step.get("providerId") and not step.get("authenticationFlow")
            and step["providerId"] not in self.magic_providers))
        workflow = str(uuid.uuid4())
        body = {"version": 1, "workflowId": workflow, "targetUserId": target["id"],
                "tenantId": int(creation["identity"]["scope"]["tenantId"]), "clientId": "app", "expiresAt": int(time.time()) + 900,
                "claimDigest": native.mac("magic-link-capability/v1", {
                    "workflowId": workflow, "token": uuid.uuid4().hex + uuid.uuid4().hex})}
        signed = proof(body, self.realm_id)
        encoded, signature = signed.split(".")
        self.assertTrue(hmac.compare_digest(
            base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
            hmac.new(native.CONTEXT_KEY, ("magic-link-proof/v1\n" + encoded).encode(), hashlib.sha256).digest()))
        OBSERVATIONS["commandMacValid"] = True
        status, reply = native.call(self.base, "POST", token_path, {
            "client_id": "app", "grant_type": "password",
            "oriso_magic_command": native.canonical(body).decode()}, actor, True, signed)
        OBSERVATIONS["magicStatus"] = status
        OBSERVATIONS["nativeRouterSelected"] = (
            isinstance(reply, dict) and reply.get("error_description") == "Claimed Magic Link session unavailable")
        self.assertEqual(200, status, "Checked native claimed-session path must issue a native session")
        self.assertTrue(reply.get("access_token"))
        def claims(response):
            encoded=response["access_token"].split(".")[1]
            return json.loads(base64.urlsafe_b64decode(encoded+"="*(-len(encoded)%4)))
        issued=claims(reply)
        TOKEN_FACTS.update(
            subjectPresent=isinstance(issued.get("sub"),str) and bool(issued.get("sub")),
            subjectMatchesTarget=issued.get("sub")==target["id"],
            subjectMatchesCanonicalAdmin=issued.get("sub")==native.SUBJECTS["ACCOUNT_ADMIN"],
            clientMatchesApp=issued.get("azp")=="app",
            tenantPresent="tenantId" in issued,
            tenantMatchesTarget=issued.get("tenantId")==creation["identity"]["scope"]["tenantId"],
            sessionIdPresent=isinstance(issued.get("sid"),str) and bool(issued.get("sid")))
        self.assertEqual(target["id"],issued.get("sub"))
        self.assertEqual("app",issued.get("azp"))
        self.assertEqual(creation["identity"]["scope"]["tenantId"],issued.get("tenantId"))
        self.assertGreater(issued.get("exp",0),time.time())
        SESSION_CHECKS["nativeSubjectClientTenantExpiry"]=True
        sid=issued.get("sid")
        self.assertTrue(isinstance(sid,str) and sid)
        def session_ids():
            return {row["id"] for row in self.admin("GET","/users/"+target["id"]+"/sessions")}
        self.assertEqual({sid},session_ids())
        SESSION_CHECKS["actualNativeSessionBound"]=True
        def exchange(command,actor_name="ACCOUNT_ADMIN",signed_body=None,proof_changes=None):
            bearer=self.token(actor_name)
            return native.call(self.base,"POST",token_path,{
                "client_id":"app","grant_type":"password","oriso_magic_command":native.canonical(command).decode()},
                bearer,True,proof(signed_body or command,self.realm_id,proof_changes))
        status,replayed=exchange(body)
        self.assertEqual(200,status)
        self.assertEqual(sid,claims(replayed).get("sid"))
        self.assertEqual({sid},session_ids())
        SESSION_CHECKS["sameWorkflowSameSession"]=True
        changed={**body,"claimDigest":"b"*64}
        self.assertEqual(401,exchange(changed)[0])
        self.assertEqual({sid},session_ids())
        SESSION_CHECKS["changedTupleRefused"]=True
        self.assertEqual(401,exchange(changed,signed_body=body)[0])
        self.assertEqual({sid},session_ids())
        SESSION_CHECKS["unboundBodyRefused"]=True
        self.assertEqual(401,exchange(body,actor_name="ACCOUNT_CREATE")[0])
        self.assertEqual({sid},session_ids())
        SESSION_CHECKS["wrongActorRefused"]=True
        self.assertEqual(401,exchange(body,proof_changes={"aud":"oriso-account-lifecycle"})[0])
        self.assertEqual({sid},session_ids())
        SESSION_CHECKS["wrongProofAudienceRefused"]=True
        self.assertEqual(401,exchange({**body,"expiresAt":int(time.time())-1})[0])
        self.assertEqual({sid},session_ids())
        SESSION_CHECKS["expiredCommandRefused"]=True
        # Confirm all rejected packets preserved the original exact workflow before final disabled case.
        status,still_owned=exchange(body)
        self.assertEqual(200,status)
        self.assertEqual(sid,claims(still_owned).get("sid"))
        self.assertEqual({sid},session_ids())
        # Existing pending required action is checked before any owned native session attach.
        try:
            self.admin("PUT","/users/"+target["id"],{**target,"requiredActions":["UPDATE_PASSWORD"]})
            self.assertEqual(["UPDATE_PASSWORD"],self.admin("GET","/users/"+target["id"])["requiredActions"])
        except AssertionError as failure:
            raise RuntimeError("Required action fixture precondition") from failure
        self.assertEqual(401,exchange(body)[0])
        self.assertEqual({sid},session_ids())
        SESSION_CHECKS["requiredActionRefused"]=True
        try:
            self.admin("PUT","/users/"+target["id"],{**target,"requiredActions":[]})
            self.assertFalse(self.admin("GET","/users/"+target["id"]).get("requiredActions"))
        except AssertionError as failure:
            raise RuntimeError("Required action fixture restoration") from failure
        # Both first sends race on an actual fresh workflow, not just a pre-existing row.
        concurrent={**body,"workflowId":str(uuid.uuid4()),"claimDigest":native.mac("magic-link-capability/v1",{"token":uuid.uuid4().hex})}
        barrier=threading.Barrier(2)
        def race():
            barrier.wait(timeout=10)
            return exchange(concurrent)
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending=[pool.submit(race) for _ in range(2)]
            replies=[future.result(timeout=40) for future in pending]
        self.assertTrue(all(status in {200,401} for status,_ in replies))
        successful=[claims(reply)["sid"] for status,reply in replies if status==200]
        self.assertTrue(successful)
        self.assertEqual(1,len(set(successful)))
        concurrent_sid=successful[0]
        self.assertNotEqual(sid,concurrent_sid)
        expected_sessions={sid,concurrent_sid}
        self.assertEqual(expected_sessions,session_ids())
        status,retried_concurrent=exchange(concurrent)
        self.assertEqual(200,status)
        self.assertEqual(concurrent_sid,claims(retried_concurrent).get("sid"))
        self.assertEqual(expected_sessions,session_ids())
        SESSION_CHECKS["concurrentSameWorkflowOneSession"]=True
        # Exact native installer credential import is fixture preparation only. Real HTTP/native
        # readback must establish it before any MFA result can count as an assertion.
        seed="native-s1-fixture-"+uuid.uuid4().hex
        credential_data={"subType":"totp","digits":6,"counter":0,"period":30,"algorithm":"HmacSHA1"}
        try:
            before_credentials=self.admin("GET","/users/"+target["id"]+"/credentials")
            self.assertFalse(any(row["type"]=="otp" for row in before_credentials))
            self.admin("PUT","/users/"+target["id"],{**target,"credentials":[{
                "type":"otp","userLabel":"S1 disposable MFA fixture", "secretData":json.dumps({"value":seed}),
                "credentialData":json.dumps(credential_data)}]})
            current=self.admin("GET","/users/"+target["id"])
            for field in ("username","email","firstName","lastName","enabled","attributes"):
                self.assertEqual(target[field],current[field])
            after_credentials=self.admin("GET","/users/"+target["id"]+"/credentials")
            otp=[row for row in after_credentials if row["type"]=="otp"]
            self.assertEqual(1,len(otp))
            self.assertTrue({row["id"] for row in before_credentials}.issubset({row["id"] for row in after_credentials}))
            for field,value in credential_data.items():
                self.assertEqual(value,json.loads(otp[0]["credentialData"])[field])
        except AssertionError as failure:
            raise RuntimeError("Native OTP credential fixture precondition") from failure
        status,challenge=exchange(body)
        self.assertEqual(400,status)
        self.assertEqual("APP",challenge.get("otpType"))
        self.assertEqual(expected_sessions,session_ids())
        status,ordinary_challenge=native.call(self.base,"POST",token_path,{
            "client_id":"app","grant_type":"password","username":username,"password":password},form=True)
        self.assertEqual(400,status)
        self.assertEqual("APP",ordinary_challenge.get("otpType"))
        def otp_code(counter):
            value=hmac.new(seed.encode(),struct.pack(">Q",counter),hashlib.sha1).digest()
            offset=value[-1]&15
            return str((struct.unpack(">I",value[offset:offset+4])[0]&0x7fffffff)%1000000).zfill(6)
        counter=int(time.time())//30
        def mfa_exchange(code):
            return native.call(self.base,"POST",token_path,{
                "client_id":"app","grant_type":"password","oriso_magic_command":native.canonical(body).decode(),"otp":code},
                self.token("ACCOUNT_ADMIN"),True,proof(body,self.realm_id))
        nearby={otp_code(counter+offset) for offset in range(-5,6)}
        wrong=next(str(value).zfill(6) for value in range(100) if str(value).zfill(6) not in nearby)
        self.assertEqual(401,mfa_exchange(wrong)[0])
        self.assertEqual(expected_sessions,session_ids())
        status,mfa_reply=mfa_exchange(otp_code(counter))
        self.assertEqual(200,status)
        self.assertEqual(sid,claims(mfa_reply).get("sid"))
        self.assertEqual(expected_sessions,session_ids())
        SESSION_CHECKS["mfaMissingWrongAndCorrect"]=True
        self.assertEqual(400,exchange(body)[0])
        self.assertEqual(expected_sessions,session_ids())
        status,mfa_retry=mfa_exchange(otp_code(counter+1))
        self.assertEqual(200,status)
        self.assertEqual(sid,claims(mfa_retry).get("sid"))
        self.assertEqual(expected_sessions,session_ids())
        SESSION_CHECKS["mfaReplayRequiresNewValidCode"]=True
        # Remove only this disposable fixture credential, then activate a real native trigger
        # which the stock grant evaluates AFTER the final authenticator.
        try:
            self.admin("DELETE","/users/"+target["id"]+"/credentials/"+otp[0]["id"])
            self.assertFalse(any(row["type"]=="otp" for row in self.admin("GET","/users/"+target["id"]+"/credentials")))
            self.admin("PUT","/users/"+target["id"],{**target,"emailVerified":False,"requiredActions":[]})
            realm=self.admin("GET","")
            self.admin("PUT","",{**realm,"verifyEmail":True})
            self.assertTrue(self.admin("GET","")["verifyEmail"])
            self.assertIs(False,self.admin("GET","/users/"+target["id"])["emailVerified"])
            self.assertFalse(self.admin("GET","/users/"+target["id"]).get("requiredActions"))
        except AssertionError as failure:
            raise RuntimeError("Native late required action fixture precondition") from failure
        late={**body,"workflowId":str(uuid.uuid4()),"claimDigest":native.mac("magic-link-capability/v1",{"token":uuid.uuid4().hex})}
        self.assertEqual(400,exchange(late)[0])
        self.assertEqual(expected_sessions,session_ids(),"Failed native required-action trigger must not leave an orphan session")
        SESSION_CHECKS["lateRequiredActionNoOrphan"]=True
        try:
            self.admin("PUT","",realm)
            self.admin("PUT","/users/"+target["id"],target)
        except AssertionError as failure:
            raise RuntimeError("Native late required action fixture restoration") from failure
        self.admin("PUT","/users/"+target["id"],{**target,"enabled":False})
        self.assertIs(False,self.admin("GET","/users/"+target["id"])["enabled"])
        self.assertEqual(401,exchange(body)[0])
        self.assertEqual(expected_sessions,session_ids())
        SESSION_CHECKS["currentDisabledRefused"]=True
