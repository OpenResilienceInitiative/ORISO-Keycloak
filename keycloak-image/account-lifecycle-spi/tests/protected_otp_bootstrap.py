"""Original OTP GET for an actual human-approved disabled pending account."""

import base64
import copy
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import struct
import time
import threading
import unittest
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
import uuid

from lifecycle_fixture import ACTORS, CONTEXT_KEY, IMAGE, REALM, SUBJECTS, call, canonical, mac
from protected_binding_readiness import NativeFixture


class BootstrapFixture(NativeFixture):
    @classmethod
    def setUpClass(cls):
        jar = Path(os.environ.get("OTP_C_TEST_JAR", ""))
        if not jar.is_file():
            raise AssertionError("Actual paired OTP provider required")
        cls.otp_jar = jar.resolve()
        cls.otp_jar_sha256 = hashlib.sha256(cls.otp_jar.read_bytes()).hexdigest()
        source = Path(__file__).resolve().parents[2] / "otp-config-spi/tests/scenario_c_otp_fixture.py"
        spec = importlib.util.spec_from_file_location("bootstrap_otp_mail_fixture", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.mail = module.MailSink(("0.0.0.0", 0), module.MailSink.Handler)
        cls.mail.messages = []
        cls.addClassCleanup(cls.mail.server_close)
        cls.addClassCleanup(cls.mail.shutdown)
        threading.Thread(target=cls.mail.serve_forever, daemon=True).start()
        original = subprocess.run

        def launch(args, *positional, **keywords):
            if isinstance(args, list) and args[:2] == ["docker", "run"]:
                args = args.copy()
                index = args.index(IMAGE)
                args[index:index] = [
                    "-v", str(cls.otp_jar) + ":/opt/keycloak/providers/otp-config-spi.jar:ro",
                    "-e", "IDENTITY_ACCOUNT_ADMIN_CLIENT_ID=backend-account-admin",
                    "-e", "ORISO_APP_BASE_URL=https://otp-fixture.internal",
                    "-e", "EMAIL_BRANDING_NAME=OTP Fixture",
                    "-e", "EMAIL_LEGAL_ORGANISATION_NAME=Fixture Operator",
                    "-v", str(Path(__file__).resolve().parents[2] / "themes/oriso") + ":/opt/keycloak/themes/oriso:ro",
                    "--add-host", "host.docker.internal:host-gateway",
                ]
            return original(args, *positional, **keywords)

        subprocess.run = launch
        try:
            super().setUpClass()
        finally:
            subprocess.run = original
        if hashlib.sha256(cls.otp_jar.read_bytes()).hexdigest() != cls.otp_jar_sha256:
            raise AssertionError("Paired OTP provider changed during native launch")


REQUIRED = (
    "sameSourceBothProvidersMountedReadOnly",
    "allFiveCurrentNativeLinksVerified",
    "actualHumanApprovalAndPendingCreateVerified",
    "actualExactOwnedReadVerified",
    "disabledPendingNativeProfileAndNoOtpVerified",
    "canonicalAdminThreeAudiencesAndRolesVerified",
    "stockNativeAdminReadDenied",
    "bootstrapDeadlineOnlyReducesApprovalAndMachine",
    "nativeAccountAndCredentialsUnchangedByRead",
    "originalMachineExpiryElapsedBeforeApp",
    "freshCanonicalAdminVerifiedForApp",
)


def classify(summary):
    observed = summary.get("readinessObservation", {})
    if not (
        summary.get("executed") == 1
        and summary.get("errors") == summary.get("skipped") == 0
        and summary.get("bothProvidersStable") is True
        and summary.get("bootstrapWorkflowStable") is True
        and all(observed.get(key) is True for key in REQUIRED)
        and observed.get("sourceApproveStatus") == 201
        and observed.get("sourceCreateStatus") == 201
        and observed.get("sourceOwnedReadStatus") == 200
        and len(summary.get("nativeImageIds", [])) == 2
        and len(set(summary["nativeImageIds"])) == 1
    ):
        return "INPUT_OR_FIXTURE_ERROR"
    if summary.get("failures") == 1 and observed.get("otpPrepareStatus") == 403:
        return "GENUINE_PROTECTED_PENDING_OTP_PREPARE_RED"
    if (summary.get("failures") == 1 and observed.get("otpPrepareStatus") == 200
        and observed.get("preparedReceiptMacVerified") is True
        and observed.get("appMutationStatus") == 403
        and observed.get("noAppCredentialBeforeMutation") is True):
        return "GENUINE_PROTECTED_PENDING_OTP_APP_RED"
    if (summary.get("failures") == 1 and observed.get("otpPrepareStatus") == 200
        and observed.get("preparedReceiptMacVerified") is True
        and observed.get("expiredOriginalPrepareRetryStatus") == 403):
        return "GENUINE_PROTECTED_PENDING_OTP_EXPIRED_PREPARE_RETRY_RED"
    email_ready = all(observed.get(key) is True for key in (
        "emailPendingCreateOwnedReadAndPrepareVerified", "emailActualSmtpConfigured",
        "emailCanonicalAdminAndStockDenialVerified", "emailNoCredentialOrMailBeforeStart"))
    if (summary.get("failures") == 1 and email_ready and observed.get("emailStartStatus") == 403):
        return "GENUINE_PROTECTED_PENDING_OTP_EMAIL_START_RED"
    if (summary.get("failures") == 1 and email_ready
        and observed.get("emailStartStatus") == 202 and observed.get("emailSentStatus") == 200
        and observed.get("emailExactlyOneRealSmtpAndNativeInactiveCredential") is True
        and observed.get("emailFinishStatus") == 403):
        return "GENUINE_PROTECTED_PENDING_OTP_EMAIL_FINISH_RED"
    if (summary.get("failures") == 1 and email_ready
        and observed.get("emailFinishActiveDisabledAndExactRetryVerified") is True
        and observed.get("fencedEmailCancelStatus") == 200
        and observed.get("fencedEmailRecoveryStatus") == 200
        and observed.get("fencedEmailTwoGenerationFenceVerified") is True
        and observed.get("fencedEmailOldStartStatus") in (403, 409)
        and observed.get("fencedEmailOldWriteAndSmtpUnchanged") is True
        and observed.get("fencedEmailCompensateStatus") == 409):
        return "GENUINE_FENCED_PENDING_EMAIL_COMPENSATION_RED"
    if (summary.get("failures") == 0 and observed.get("otpPrepareStatus") == 200
        and observed.get("appMutationStatus") == 201
        and all(observed.get(key) is True for key in (
            "preparedReceiptMacVerified", "appNativeCredentialAndDisabledStateVerified",
            "exactAppRetryPreservesOneCredential", "completedPhaseRefusesNewEnrollment",
            "expiredOriginalPrepareRetryPreservesExactCausalReceipt", "emailFinishActiveDisabledAndExactRetryVerified",
            "fencedEmailPendingCompensationExactRetryVerified"))):
        return "GREEN"
    return "BEHAVIOR_FAILURE"


class BootstrapRead(unittest.TestCase):
    observation = {}

    def clean_native(self):
        BootstrapFixture.doClassCleanups()
        self.assertEqual([], BootstrapFixture.tearDown_exceptions)

    def test_actual_pending_protected_claim_prepares_original_otp_route(self):
        type(self).observation = {}
        observed = self.observation
        self.addCleanup(self.clean_native)
        BootstrapFixture.setUpClass()
        helper = BootstrapFixture("runTest")
        self.assertTrue(BootstrapFixture.configuration_checked)
        container = json.loads(subprocess.run(
            ["docker", "inspect", BootstrapFixture.name], check=True,
            capture_output=True, text=True, timeout=15,
        ).stdout)[0]
        for destination, source in [
            ("account-lifecycle-spi.jar", BootstrapFixture.jar_path),
            ("otp-config-spi.jar", BootstrapFixture.otp_jar),
        ]:
            mounts = [row for row in container["Mounts"] if row["Destination"]
                      == "/opt/keycloak/providers/" + destination]
            self.assertEqual(1, len(mounts))
            self.assertEqual(str(source), mounts[0]["Source"])
            self.assertFalse(mounts[0]["RW"])
        observed["sameSourceBothProvidersMountedReadOnly"] = True
        for actor, (client, _) in ACTORS.items():
            clients = helper.admin("GET", "/clients?clientId=" + client)
            self.assertEqual(1, len(clients))
            self.assertEqual(SUBJECTS[actor], helper.admin(
                "GET", "/clients/" + clients[0]["id"] + "/service-account-user"
            )["id"])
        observed["allFiveCurrentNativeLinksVerified"] = True
        approval, attempt, scope, approved, create = helper.approved_creation()
        observed["sourceApproveStatus"] = 201
        status, opened = helper.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt
        )
        observed["sourceCreateStatus"] = status
        self.assertEqual(201, status)
        self.assertEqual("OPEN", opened["state"])
        observed["actualHumanApprovalAndPendingCreateVerified"] = True
        read = {key: copy.deepcopy(create[key]) for key in (
            "approvalReceipt", "scopeDigest", "authorizationRevision",
            "creationFingerprint", "execution",
        )}
        read.update(accountId=opened["accountId"], creationProof=opened["creationProof"])
        status, projection = helper.protected_machine_request(
            "owned-read", approval, read, actor="ACCOUNT_CREATE", attempt=attempt
        )
        observed["sourceOwnedReadStatus"] = status
        self.assertEqual(200, status)
        self.assertEqual(opened["accountId"], projection["id"])
        self.assertFalse(projection["enabled"])
        self.assertEqual([], projection["effectiveRoles"])
        observed["actualExactOwnedReadVerified"] = True
        account = opened["accountId"]
        native = helper.admin("GET", "/users/" + account)
        credentials = helper.admin("GET", "/users/" + account + "/credentials")
        self.assertFalse(native["enabled"])
        self.assertEqual(["password"], [row["type"] for row in credentials])
        self.assertEqual(["/pending-provisioning"], [row["path"] for row in
            helper.admin("GET", "/users/" + account + "/groups")])
        observed["disabledPendingNativeProfileAndNoOtpVerified"] = True
        # Actual native client lifetime, already supported by the retained native expiry fixture.
        admin_client = helper.admin("GET", "/clients?clientId=backend-account-admin")[0]
        admin_client.setdefault("attributes", {})["access.token.lifespan"] = "20"
        helper.admin("PUT", "/clients/" + admin_client["id"], admin_client)
        bearer = helper.token("ACCOUNT_ADMIN")
        encoded = bearer.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        aud = claims["aud"]
        self.assertEqual({"userservice", "oriso-account-lifecycle", "oriso-otp"},
                         set([aud] if isinstance(aud, str) else aud))
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], claims["sub"])
        self.assertEqual("backend-account-admin", claims["azp"])
        self.assertEqual(set(ACTORS["ACCOUNT_ADMIN"][1]), set(claims["realm_access"]["roles"]))
        observed["canonicalAdminThreeAudiencesAndRolesVerified"] = True
        self.assertEqual(403, call(helper.base, "GET", "/admin/realms/" + REALM
                                  + "/users/" + account, token=bearer)[0])
        observed["stockNativeAdminReadDenied"] = True
        from datetime import datetime
        deadline = min(int(claims["exp"]), int(datetime.fromisoformat(
            scope["validUntil"].replace("Z", "+00:00")).timestamp()))
        self.assertGreater(deadline, int(time.time()))
        target = {
            "accountId": account, "tenantId": projection["tenantId"],
            "bootstrap": {
                "v": 1, "kind": "PROTECTED_ACCEPTANCE", "approvalId": approval,
                "scopeDigest": approved["scopeDigest"],
                "authorizationRevision": scope["authorizationRevision"],
                "acceptanceClaim": copy.deepcopy(create["acceptanceClaim"]),
                "attemptId": attempt, "execution": copy.deepcopy(create["execution"]),
                "creationFingerprint": create["creationFingerprint"],
                "creationProof": opened["creationProof"], "authorityValidUntil": deadline,
            },
        }
        observed["bootstrapDeadlineOnlyReducesApprovalAndMachine"] = True
        materialized = {"target": target, "username": projection["username"], "otp": None}
        now = int(time.time())
        proof = {
            "iss": "userservice", "aud": "oriso-otp", "purpose": "OTP",
            "operation": "otp.bootstrap-read", "method": "GET", "actor": "ACCOUNT_ADMIN",
            "realm": REALM, "target": "realm/" + helper.realm_id + "/account/" + account,
            "taskClient": ACTORS["ACCOUNT_ADMIN"][0], "taskSubject": SUBJECTS["ACCOUNT_ADMIN"],
            "payloadDigest": mac("payload", materialized), "jti": str(uuid.uuid4()),
            "nonce": uuid.uuid4().hex, "iat": now, "exp": min(now + 60, deadline),
        }
        payload = base64.urlsafe_b64encode(canonical(proof)).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(hmac.new(
            CONTEXT_KEY, ("proof\n" + payload).encode(), hashlib.sha256
        ).digest()).decode().rstrip("=")
        request = Request(helper.base + "/realms/" + REALM
            + "/otp-config/fetch-otp-setup-info/" + quote(projection["username"], safe=""),
            method="GET", headers={
                "Authorization": "Bearer " + bearer,
                "X-ORISO-Task-Context": payload + "." + signature,
                "X-ORISO-Account-Target": canonical(target).decode(),
            })
        try:
            response = urlopen(request, timeout=30)
        except HTTPError as error:
            response = error
        with response:
            status = response.code
            raw = response.read()
            result = json.loads(raw) if raw else None
        observed["otpPrepareStatus"] = status
        self.assertEqual(native, helper.admin("GET", "/users/" + account))
        self.assertEqual(credentials, helper.admin("GET", "/users/" + account + "/credentials"))
        observed["nativeAccountAndCredentialsUnchangedByRead"] = True
        self.assertEqual(200, status)
        self.assertEqual({"otpInfo", "bootstrapReceipt", "authorityValidUntil"}, set(result))
        self.assertFalse(result["otpInfo"]["otpSetup"])
        self.assertTrue(result["otpInfo"]["otpSecret"])
        self.assertTrue(result["otpInfo"]["otpSecretQrCode"])
        self.assertTrue(result["bootstrapReceipt"])
        self.assertLessEqual(result["authorityValidUntil"], deadline)

        # The native prepare receipt is causal metadata, never a public DTO authority factory.
        receipt = result["bootstrapReceipt"]
        encoded, signature = receipt.split(".")
        self.assertEqual(64, len(signature))
        expected_mac = hmac.new(CONTEXT_KEY,
            ("otp-bootstrap-prepare/v1\n" + encoded).encode(), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(signature, expected_mac))
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        receipt_value = json.loads(decoded)
        self.assertEqual(canonical(receipt_value), decoded)
        self.assertEqual({
            "v": 1, "realmId": helper.realm_id, "approvalId": approval,
            "attemptId": attempt, "accountId": account,
            "claimId": create["acceptanceClaim"]["claimId"],
            "executionId": create["execution"]["executionId"],
            "bootstrapIncarnation": create["execution"]["executionId"],
            "ownerClient": ACTORS["ACCOUNT_ADMIN"][0], "ownerSubject": SUBJECTS["ACCOUNT_ADMIN"],
            "originDigest": mac("otp-bootstrap-origin/v1", target),
            "authorityValidUntil": result["authorityValidUntil"], "state": "PREPARED",
        }, receipt_value)
        observed["preparedReceiptMacVerified"] = True
        self.assertEqual(int(claims["exp"]), deadline)
        remaining = deadline - int(time.time())
        self.assertGreaterEqual(remaining, 1)
        self.assertLessEqual(remaining, 20)
        observed["originalPrepareRemainingSeconds"] = remaining
        time.sleep(remaining + 2)
        self.assertGreater(int(time.time()), int(claims["exp"]))
        observed["originalMachineExpiryElapsedBeforeApp"] = True
        bearer = helper.token("ACCOUNT_ADMIN")
        fresh_encoded = bearer.split(".")[1]
        fresh_claims = json.loads(base64.urlsafe_b64decode(
            fresh_encoded + "=" * (-len(fresh_encoded) % 4)))
        for name in ("sub", "azp", "aud", "realm_access"):
            self.assertEqual(claims[name], fresh_claims[name])
        self.assertGreater(int(fresh_claims["exp"]), int(time.time()))
        self.assertGreater(int(fresh_claims["iat"]), int(claims["iat"]))
        observed["freshCanonicalAdminVerifiedForApp"] = True
        # A lost preparation reply must remain recoverable with the exact old body,
        # current recipient provenance and a fresh native ADMIN; no deadline/body refresh.
        now = int(time.time())
        retry_proof = {**proof, "jti": str(uuid.uuid4()), "nonce": uuid.uuid4().hex,
            "iat": now, "exp": min(now + 60, int(fresh_claims["exp"]))}
        encoded_retry = base64.urlsafe_b64encode(canonical(retry_proof)).decode().rstrip("=")
        retry_mac = base64.urlsafe_b64encode(hmac.new(CONTEXT_KEY,
            ("proof\n" + encoded_retry).encode(), hashlib.sha256).digest()).decode().rstrip("=")
        retry_request = Request(request.full_url, method="GET", headers={
            "Authorization": "Bearer " + bearer,
            "X-ORISO-Task-Context": encoded_retry + "." + retry_mac,
            "X-ORISO-Account-Target": canonical(target).decode(),
        })
        try:
            reply = urlopen(retry_request, timeout=30)
        except HTTPError as error:
            reply = error
        with reply:
            retry_status, retry_raw = reply.code, reply.read()
        observed["expiredOriginalPrepareRetryStatus"] = retry_status
        self.assertEqual(200, retry_status)
        recovered = json.loads(retry_raw)
        self.assertEqual({"otpInfo", "bootstrapReceipt", "authorityValidUntil"}, set(recovered))
        self.assertEqual(receipt, recovered["bootstrapReceipt"])
        self.assertEqual(result["authorityValidUntil"], recovered["authorityValidUntil"])
        self.assertFalse(recovered["otpInfo"]["otpSetup"])
        self.assertTrue(recovered["otpInfo"]["otpSecret"])
        self.assertTrue(recovered["otpInfo"]["otpSecretQrCode"])
        self.assertEqual(credentials, helper.admin("GET", "/users/" + account + "/credentials"))
        observed["expiredOriginalPrepareRetryPreservesExactCausalReceipt"] = True
        secret = result["otpInfo"]["otpSecret"]
        digest = hmac.new(secret.encode(), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
        offset = digest[-1] & 15
        code = str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)
        mutation_target = {"accountId": account, "tenantId": projection["tenantId"], "origin": {
            "kind": "INVITATION", "workflowId": scope["workflowId"], "humanSubject": None,
            "humanIssuer": None, "humanClient": None, "humanAuthority": None,
        }}
        mutation = {"target": mutation_target, "operationId": str(uuid.uuid4()),
            "expectedState": mac("otp-bootstrap-state/v1", receipt),
            "otp": {"initialCode": code, "secret": secret, "email": None}}

        def app(body):
            materialized = {**copy.deepcopy(body), "username": projection["username"],
                            "bootstrapReceipt": receipt}
            now = int(time.time())
            claims = {**proof, "operation": "otp.bootstrap-app-setup", "method": "PUT",
                "payloadDigest": mac("payload", materialized), "jti": str(uuid.uuid4()),
                "nonce": uuid.uuid4().hex, "iat": now,
                "exp": min(now + 60, int(fresh_claims["exp"]))}
            payload = base64.urlsafe_b64encode(canonical(claims)).decode().rstrip("=")
            signature = base64.urlsafe_b64encode(hmac.new(CONTEXT_KEY,
                ("proof\n" + payload).encode(), hashlib.sha256).digest()).decode().rstrip("=")
            request = Request(helper.base + "/realms/" + REALM + "/otp-config/setup-otp/"
                + quote(projection["username"], safe=""), method="PUT", data=canonical(body), headers={
                    "Content-Type": "application/json", "Authorization": "Bearer " + bearer,
                    "X-ORISO-Task-Context": payload + "." + signature,
                    "X-ORISO-OTP-Bootstrap": receipt,
                })
            try:
                response = urlopen(request, timeout=30)
            except HTTPError as error:
                response = error
            with response:
                raw = response.read()
                return response.code, json.loads(raw) if raw else None

        observed["noAppCredentialBeforeMutation"] = credentials == helper.admin(
            "GET", "/users/" + account + "/credentials")
        status, completed = app(mutation)
        observed["appMutationStatus"] = status
        self.assertEqual(201, status)
        self.assertEqual({"status", "result", "receipt"}, set(completed))
        self.assertEqual(201, completed["status"])
        self.assertTrue(completed["receipt"])
        after = helper.admin("GET", "/users/" + account + "/credentials")
        self.assertEqual(["otp", "password"], sorted(row["type"] for row in after))
        self.assertFalse(helper.admin("GET", "/users/" + account)["enabled"])
        self.assertEqual(["/pending-provisioning"], [row["path"] for row in
            helper.admin("GET", "/users/" + account + "/groups")])
        observed["appNativeCredentialAndDisabledStateVerified"] = True
        status, retry = app(copy.deepcopy(mutation))
        self.assertEqual(201, status)
        self.assertEqual(completed, retry)
        self.assertEqual(after, helper.admin("GET", "/users/" + account + "/credentials"))
        observed["exactAppRetryPreservesOneCredential"] = True
        changed = copy.deepcopy(mutation)
        changed["operationId"] = str(uuid.uuid4())
        self.assertEqual(409, app(changed)[0])
        self.assertEqual(after, helper.admin("GET", "/users/" + account + "/credentials"))
        observed["completedPhaseRefusesNewEnrollment"] = True

        self.email_pending(helper, observed)
        self.email_pending(helper, observed, fenced_cleanup=True)

    def email_pending(self, helper, observed, fenced_cleanup=False):
        from email import policy as email_policy
        from email.parser import BytesParser
        import re
        approval, attempt, scope, approved, create = helper.approved_creation()
        status, opened = helper.protected_machine_request(
            "create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt)
        self.assertEqual(201, status)
        owned = {key: copy.deepcopy(create[key]) for key in (
            "approvalReceipt", "scopeDigest", "authorizationRevision", "creationFingerprint", "execution")}
        owned.update(accountId=opened["accountId"], creationProof=opened["creationProof"])
        status, projection = helper.protected_machine_request(
            "owned-read", approval, owned, actor="ACCOUNT_CREATE", attempt=attempt)
        self.assertEqual(200, status)
        self.assertFalse(projection["enabled"])
        account, username = opened["accountId"], projection["username"]
        baseline = helper.admin("GET", "/users/" + account + "/credentials")
        self.assertEqual(["password"], [row["type"] for row in baseline])

        def invoke(operation, method, route, body=None, target=None, receipt=None):
            bearer = helper.token("ACCOUNT_ADMIN")
            encoded = bearer.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            self.assertEqual({"userservice", "oriso-account-lifecycle", "oriso-otp"}, set(claims["aud"]))
            self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], claims["sub"])
            self.assertEqual(ACTORS["ACCOUNT_ADMIN"][0], claims["azp"])
            self.assertEqual(403, call(helper.base, "GET", "/admin/realms/" + REALM
                + "/users/" + account, token=bearer)[0])
            observed["emailCanonicalAdminAndStockDenialVerified"] = True
            materialized = {"target": target, "username": username, "otp": None} if method == "GET" else {
                **copy.deepcopy(body), "username": username, "bootstrapReceipt": receipt}
            now = int(time.time())
            facts = {"iss": "userservice", "aud": "oriso-otp", "purpose": "OTP",
                "operation": operation, "method": method, "actor": "ACCOUNT_ADMIN", "realm": REALM,
                "target": "realm/" + helper.realm_id + "/account/" + account,
                "taskClient": ACTORS["ACCOUNT_ADMIN"][0], "taskSubject": SUBJECTS["ACCOUNT_ADMIN"],
                "payloadDigest": mac("payload", materialized), "jti": str(uuid.uuid4()),
                "nonce": uuid.uuid4().hex, "iat": now, "exp": min(now + 60, int(claims["exp"]))}
            payload = base64.urlsafe_b64encode(canonical(facts)).decode().rstrip("=")
            signature = base64.urlsafe_b64encode(hmac.new(CONTEXT_KEY,
                ("proof\n" + payload).encode(), hashlib.sha256).digest()).decode().rstrip("=")
            headers = {"Authorization": "Bearer " + bearer, "X-ORISO-Task-Context": payload + "." + signature}
            if target is not None:
                headers["X-ORISO-Account-Target"] = canonical(target).decode()
            if receipt is not None:
                headers["X-ORISO-OTP-Bootstrap"] = receipt
            if body is not None:
                headers["Content-Type"] = "application/json"
            request = Request(helper.base + "/realms/" + REALM + "/otp-config/" + route
                + "/" + quote(username, safe=""), method=method,
                data=None if body is None else canonical(body), headers=headers)
            try:
                reply = urlopen(request, timeout=30)
            except HTTPError as error:
                reply = error
            with reply:
                raw = reply.read()
                return reply.code, json.loads(raw) if raw else None

        from datetime import datetime
        workflow_deadline = int(datetime.fromisoformat(scope["validUntil"].replace("Z", "+00:00")).timestamp())
        target = {"accountId": account, "tenantId": projection["tenantId"], "bootstrap": {
            "v": 1, "kind": "PROTECTED_ACCEPTANCE", "approvalId": approval,
            "scopeDigest": approved["scopeDigest"], "authorizationRevision": scope["authorizationRevision"],
            "acceptanceClaim": copy.deepcopy(create["acceptanceClaim"]), "attemptId": attempt,
            "execution": copy.deepcopy(create["execution"]), "creationFingerprint": create["creationFingerprint"],
            "creationProof": opened["creationProof"], "authorityValidUntil": workflow_deadline}}
        status, prepared = invoke("otp.bootstrap-read", "GET", "fetch-otp-setup-info", target=target)
        self.assertEqual(200, status)
        self.assertFalse(prepared["otpInfo"]["otpSetup"])
        receipt = prepared["bootstrapReceipt"]
        encoded, signature = receipt.split(".")
        self.assertTrue(hmac.compare_digest(signature, hmac.new(CONTEXT_KEY,
            ("otp-bootstrap-prepare/v1\n" + encoded).encode(), hashlib.sha256).hexdigest()))
        observed["emailPendingCreateOwnedReadAndPrepareVerified"] = True
        realm = helper.admin("GET", "")
        realm["emailTheme"] = "oriso"
        realm["smtpServer"] = {"host": "host.docker.internal", "port": str(BootstrapFixture.mail.server_address[1]),
            "from": "otp-fixture@oriso.org", "auth": "false", "ssl": "false", "starttls": "false"}
        helper.admin("PUT", "", realm)
        self.assertEqual(realm["smtpServer"], helper.admin("GET", "")["smtpServer"])
        observed["emailActualSmtpConfigured"] = True
        before = len(BootstrapFixture.mail.messages)
        mutation_target = {"accountId": account, "tenantId": projection["tenantId"], "origin": {
            "kind": "INVITATION", "workflowId": scope["workflowId"], "humanSubject": None,
            "humanIssuer": None, "humanClient": None, "humanAuthority": None}}
        start = {"target": mutation_target, "operationId": str(uuid.uuid4()),
            "expectedState": mac("otp-bootstrap-state/v1", receipt), "authorityValidUntil": workflow_deadline,
            "otp": {"initialCode": None, "secret": None, "email": scope["recipient"]}}
        observed["emailNoCredentialOrMailBeforeStart"] = baseline == helper.admin(
            "GET", "/users/" + account + "/credentials") and before == len(BootstrapFixture.mail.messages)
        status, ready = invoke("otp.bootstrap-email-start", "PUT", "send-verification-mail", start, receipt=receipt)
        observed["emailStartStatus"] = status
        if status == 403:
            self.assertEqual(baseline, helper.admin("GET", "/users/" + account + "/credentials"))
            self.assertEqual(before, len(BootstrapFixture.mail.messages))
        self.assertEqual(202, status)
        self.assertEqual("READY", ready["deliveryState"])
        status, sent = invoke("otp.bootstrap-email-start", "PUT", "send-verification-mail", start, receipt=receipt)
        observed["emailSentStatus"] = status
        self.assertEqual(200, status)
        self.assertEqual("SENT", sent["deliveryState"])
        self.assertEqual(before + 1, len(BootstrapFixture.mail.messages))
        credentials = helper.admin("GET", "/users/" + account + "/credentials")
        mail = [row for row in credentials if row["type"] == "MAIL_OTP_CM"]
        self.assertEqual(1, len(mail))
        self.assertFalse(json.loads(mail[0]["credentialData"])["active"])
        observed["emailExactlyOneRealSmtpAndNativeInactiveCredential"] = True
        if fenced_cleanup:
            cancel = {"cancellationId": str(uuid.uuid4()), "scopeDigest": approved["scopeDigest"],
                "workflowId": scope["workflowId"], "inviteId": scope["inviteId"],
                "authorizationRevision": scope["authorizationRevision"], "reason": "REVOKED",
                "absentScope": None, "approvalRequestDigest": approved["approvalRequestDigest"]}
            status, cancelled = helper.protected_machine_request("cancel", approval, cancel)
            observed["fencedEmailCancelStatus"] = status
            self.assertEqual(200, status)
            self.assertEqual("CANCELLED", cancelled["state"])
            fence = cancelled["fencedExecution"]
            self.assertEqual(1, fence["generation"])
            self.assertNotEqual(create["execution"]["executionId"], fence["executionId"])
            recover = {key: copy.deepcopy(create[key]) for key in (
                "approvalReceipt", "scopeDigest", "authorizationRevision", "creationFingerprint", "acceptanceClaim")}
            recover.update(expectedGeneration=fence["generation"], recoveryId=str(uuid.uuid4()))
            status, claimed = helper.protected_machine_request(
                "recover", approval, recover, actor="ACCOUNT_ADMIN", attempt=attempt)
            observed["fencedEmailRecoveryStatus"] = status
            self.assertEqual(200, status)
            self.assertEqual("RECOVERY_CLAIMED", claimed["state"])
            self.assertEqual({"executionId": recover["recoveryId"], "generation": 2}, claimed["execution"])
            self.assertEqual(opened["creationProof"], claimed["creationProof"])
            observed["fencedEmailTwoGenerationFenceVerified"] = True
            frozen_credentials = helper.admin("GET", "/users/" + account + "/credentials")
            old_status, _ = invoke("otp.bootstrap-email-start", "PUT", "send-verification-mail", start, receipt=receipt)
            observed["fencedEmailOldStartStatus"] = old_status
            self.assertIn(old_status, (403, 409))
            self.assertEqual(frozen_credentials, helper.admin("GET", "/users/" + account + "/credentials"))
            self.assertEqual(before + 1, len(BootstrapFixture.mail.messages))
            observed["fencedEmailOldWriteAndSmtpUnchanged"] = True
            cleanup = {key: copy.deepcopy(create[key]) for key in (
                "approvalReceipt", "scopeDigest", "authorizationRevision", "creationFingerprint")}
            cleanup.update(execution=claimed["execution"], accountId=account,
                creationProof=opened["creationProof"], localCleanup={"journalVersion": 1,
                "outboxId": str(uuid.uuid4()), "effectsDigest": "c" * 64})
            status, terminal = helper.protected_machine_request(
                "compensate", approval, cleanup, actor="ACCOUNT_ADMIN", attempt=attempt)
            observed["fencedEmailCompensateStatus"] = status
            self.assertEqual(200, status)
            self.assertEqual("COMPENSATED", terminal["state"])
            self.assertEqual((200, terminal), helper.protected_machine_request(
                "compensate", approval, cleanup, actor="ACCOUNT_ADMIN", attempt=attempt))
            self.assertEqual([], helper.admin("GET", "/users?username=" + quote(username, safe="") + "&exact=true"))
            self.assertEqual(before + 1, len(BootstrapFixture.mail.messages))
            observed["fencedEmailPendingCompensationExactRetryVerified"] = True
            return
        message = BytesParser(policy=email_policy.default).parsebytes(BootstrapFixture.mail.messages[-1])
        codes = set()
        for part in message.walk():
            if part.get_content_type() in {"text/plain", "text/html"}:
                text = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
                codes.update(re.findall(r"(?<![0-9])[0-9]{6}(?![0-9])", text))
        self.assertEqual(1, len(codes))
        finish = {"target": mutation_target, "operationId": str(uuid.uuid4()),
            "expectedState": mac("otp-bootstrap-state/v1", receipt), "emailStartOperationId": start["operationId"],
            "otp": {"initialCode": next(iter(codes)), "secret": None, "email": None}}
        status, completed = invoke("otp.bootstrap-email-finish", "POST", "setup-otp-mail", finish, receipt=receipt)
        observed["emailFinishStatus"] = status
        self.assertEqual(201, status)
        current = helper.admin("GET", "/users/" + account)
        self.assertFalse(current["enabled"])
        self.assertEqual(scope["recipient"], current["email"])
        current_mail = [row for row in helper.admin("GET", "/users/" + account + "/credentials") if row["type"] == "MAIL_OTP_CM"]
        self.assertEqual(1, len(current_mail))
        self.assertTrue(json.loads(current_mail[0]["credentialData"])["active"])
        self.assertEqual((201, completed), invoke("otp.bootstrap-email-finish", "POST", "setup-otp-mail", finish, receipt=receipt))
        self.assertEqual(before + 1, len(BootstrapFixture.mail.messages))
        observed["emailFinishActiveDisabledAndExactRetryVerified"] = True
