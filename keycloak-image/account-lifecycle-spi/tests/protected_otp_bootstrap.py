"""Original OTP GET for an actual human-approved disabled pending account."""

import base64
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import struct
import time
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
    if (summary.get("failures") == 0 and observed.get("otpPrepareStatus") == 200
        and observed.get("appMutationStatus") == 201
        and all(observed.get(key) is True for key in (
            "preparedReceiptMacVerified", "appNativeCredentialAndDisabledStateVerified",
            "exactAppRetryPreservesOneCredential", "completedPhaseRefusesNewEnrollment"))):
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
                "nonce": uuid.uuid4().hex, "iat": now, "exp": min(now + 60, deadline)}
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
