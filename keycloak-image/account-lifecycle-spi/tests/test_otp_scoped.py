"""Original OTP GET under actual canonical ADMIN and current native ordinary SELF."""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
import unittest
import uuid
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from lifecycle_fixture import ACTORS, CONTEXT_KEY, REALM, SUBJECTS, call, canonical, mac
from maintenance_human_fixture import CLIENT, ISSUER, HumanMaintenanceFixture


class ScopedOtpRead(HumanMaintenanceFixture, unittest.TestCase):
    @classmethod
    def extra_launch_arguments(cls):
        jar = Path(os.environ.get("OTP_C_TEST_JAR", ""))
        if not jar.is_file():
            raise AssertionError("Actual compiled OTP provider is required")
        return [
            "-v", str(jar.resolve()) + ":/opt/keycloak/providers/otp-config-spi.jar:ro",
            "-e", "IDENTITY_ACCOUNT_ADMIN_CLIENT_ID=backend-account-admin",
            "-e", "ORISO_APP_BASE_URL=https://otp-fixture.internal",
            "-e", "EMAIL_BRANDING_NAME=OTP Fixture",
            "-e", "EMAIL_LEGAL_ORGANISATION_NAME=Fixture Operator",
        ]

    @classmethod
    def reviewed_self_operations(cls):
        return ["account.read", "account.locale", "otp.read", "otp.app-setup",
                "otp.delete", "otp.email-start", "otp.email-finish"]

    def target(self):
        return {
            "accountId": self.account_id,
            "tenantId": "11",
            "origin": {
                "kind": "SELF", "workflowId": str(uuid.uuid4()),
                "humanSubject": self.account_id, "humanIssuer": ISSUER,
                "humanClient": CLIENT, "humanAuthority": None,
            },
        }

    def scoped_read(self, human, target, expected, actor="ACCOUNT_ADMIN", mutate=False):
        username = self.creation_input["account"]["username"]
        body = {"target": target, "username": username, "otp": None}
        now = int(time.time())
        claims = {
            "iss": "userservice", "aud": "oriso-otp", "purpose": "OTP",
            "operation": "otp.read", "method": "GET", "actor": actor,
            "realm": REALM,
            "target": "realm/" + self.realm_id + "/account/" + self.account_id,
            "taskClient": ACTORS[actor][0], "taskSubject": SUBJECTS[actor],
            "payloadDigest": mac("payload", body), "jti": str(uuid.uuid4()),
            "nonce": uuid.uuid4().hex, "iat": now, "exp": now + 60,
        }
        encoded = base64.urlsafe_b64encode(canonical(claims)).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(
            hmac.new(CONTEXT_KEY, ("proof\n" + encoded).encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        if mutate:
            target = json.loads(json.dumps(target))
            target["origin"]["workflowId"] = str(uuid.uuid4())
        headers = {
            "Authorization": "Bearer " + self.token(actor),
            "X-ORISO-Task-Context": encoded + "." + signature,
            "X-ORISO-Account-Target": canonical(target).decode(),
            "X-ORISO-Human-Authorization": "Bearer " + human,
        }
        request = Request(
            self.base + "/realms/" + REALM + "/otp-config/fetch-otp-setup-info/"
            + quote(username, safe=""), headers=headers, method="GET",
        )
        try:
            with urlopen(request, timeout=30) as response:
                status, raw = response.status, response.read()
        except HTTPError as error:
            status, raw = error.code, error.read()
            error.close()
        self.phase("scoped-otp-http", operation="otp.read", actor=actor,
                   status=status, expected_status=expected)
        return status, json.loads(raw) if raw else None

    def test_canonical_admin_current_self_reads_setup_without_native_grants(self):
        human = self.human()
        bearer = self.token("ACCOUNT_ADMIN")
        encoded = bearer.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        aud = claims["aud"]
        self.assertEqual(
            {"userservice", "oriso-account-lifecycle", "oriso-otp"},
            set([aud] if isinstance(aud, str) else aud),
        )
        self.assertEqual(403, call(
            self.base, "GET", "/admin/realms/" + REALM + "/users/" + self.account_id,
            token=bearer,
        )[0])
        self.phase("scoped-otp-preconditions", canonical_admin=True,
                   exact_three_audiences=True, stock_native_denied=True,
                   actual_self_human=True, committed_ordinary_target=True)
        status, result = self.scoped_read(human, self.target(), 200)
        self.assertEqual(200, status)
        self.assertFalse(result["otpSetup"])
        self.assertTrue(result.get("otpSecret"))
        self.assertTrue(result.get("otpSecretQrCode"))

    def scoped_app_setup(self, human, body):
        username = self.creation_input["account"]["username"]
        materialized = {**body, "username": username}
        now = int(time.time())
        claims = {
            "iss": "userservice", "aud": "oriso-otp", "purpose": "OTP",
            "operation": "otp.app-setup", "method": "PUT", "actor": "ACCOUNT_ADMIN",
            "realm": REALM,
            "target": "realm/" + self.realm_id + "/account/" + self.account_id,
            "taskClient": ACTORS["ACCOUNT_ADMIN"][0], "taskSubject": SUBJECTS["ACCOUNT_ADMIN"],
            "payloadDigest": mac("payload", materialized), "jti": str(uuid.uuid4()),
            "nonce": uuid.uuid4().hex, "iat": now, "exp": now + 60,
        }
        encoded = base64.urlsafe_b64encode(canonical(claims)).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(hmac.new(
            CONTEXT_KEY, ("proof\n" + encoded).encode(), hashlib.sha256).digest()).decode().rstrip("=")
        request = Request(
            self.base + "/realms/" + REALM + "/otp-config/setup-otp/" + quote(username, safe=""),
            data=canonical(body), method="PUT", headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.token("ACCOUNT_ADMIN"),
                "X-ORISO-Task-Context": encoded + "." + signature,
                "X-ORISO-Human-Authorization": "Bearer " + human,
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                status, raw = response.status, response.read()
        except HTTPError as error:
            status, raw = error.code, error.read()
            error.close()
        self.phase("scoped-otp-app-setup-http", status=status, expected_status=201)
        return status, json.loads(raw) if raw else None

    def test_current_self_app_enrollment_retry_never_replaces_later_credentials(self):
        import struct
        human, target = self.human(), self.target()
        status, setup = self.scoped_read(human, target, 200)
        self.assertEqual(200, status)
        self.assertFalse(setup["otpSetup"])
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        self.assertRegex(current["state"], r"^[0-9a-f]{64}$")
        bearer = self.token("ACCOUNT_ADMIN")
        encoded = bearer.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        audience = claims["aud"]
        self.assertEqual({"userservice", "oriso-account-lifecycle", "oriso-otp"},
                         set([audience] if isinstance(audience, str) else audience))
        self.assertEqual(403, call(self.base, "GET", "/admin/realms/" + REALM
                                  + "/users/" + self.account_id, token=bearer)[0])
        self.assertIn("otp.app-setup", self.reviewed_self_operations())
        seed = setup["otpSecret"]
        digest = hmac.new(seed.encode(), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
        offset = digest[-1] & 15
        code = str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)
        body = {"target": target, "operationId": str(uuid.uuid4()),
                "expectedState": current["state"],
                "otp": {"initialCode": code, "secret": seed, "email": None}}
        self.phase("scoped-otp-app-setup-preconditions", canonical_admin=True,
                   stock_native_denied=True, actual_self_human=True,
                   committed_ordinary_target=True, scoped_setup_read=True,
                   frozen_current_state=True, reviewed_app_selector=True)
        status, result = self.scoped_app_setup(human, body)
        self.assertEqual(201, status)
        self.assertEqual(body["operationId"], result["operationId"])
        self.assertEqual(self.account_id, result["accountId"])
        self.assertEqual(201, result["status"])
        encoded, signature = result["receipt"].split(".")
        expected = hmac.new(CONTEXT_KEY, ("otp-operation-receipt\n" + encoded).encode(), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(expected, signature))
        receipt = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(ACTORS["ACCOUNT_ADMIN"][0], receipt["ownerClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], receipt["ownerSubject"])
        self.assertEqual("otp.app-setup", receipt["operation"])
        self.assertNotIn("secret", receipt)
        self.assertNotIn("initialCode", receipt)
        credentials = self.admin("GET", "/users/" + self.account_id + "/credentials")
        enrolled = [c for c in credentials if c["type"] == "otp"]
        self.assertEqual(1, len(enrolled))
        self.admin("DELETE", "/users/" + self.account_id + "/credentials/" + enrolled[0]["id"])
        status, retried = self.scoped_app_setup(human, body)
        self.assertEqual(201, status)
        self.assertEqual(result, retried)
        self.assertFalse(self.scoped_read(human, self.target(), 200)[1]["otpSetup"])
        self.phase("scoped-otp-app-exact-retry", admin_receipt_owner=True,
                   saved_receipt_equal=True, no_reenrollment=True)

    def test_create_actor_cannot_read_setup(self):
        self.assertEqual(403, self.scoped_read(self.human(), self.target(), 403,
                                              actor="ACCOUNT_CREATE")[0])

    def test_proof_target_mix_cannot_read_setup(self):
        self.assertEqual(403, self.scoped_read(self.human(), self.target(), 403,
                                              mutate=True)[0])

    def test_foreign_tenant_cannot_read_setup(self):
        target = self.target()
        target["tenantId"] = "12"
        self.assertEqual(403, self.scoped_read(self.human(), target, 403)[0])

    def test_asserted_foreign_human_cannot_read_setup(self):
        target = self.target()
        target["origin"]["humanSubject"] = str(uuid.uuid4())
        self.assertEqual(403, self.scoped_read(self.human(), target, 403)[0])
