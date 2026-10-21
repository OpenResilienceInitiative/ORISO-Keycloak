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

    def setUp(self):
        super().setUp()
        self.addCleanup(self.remove_fixture_app_credentials)

    def remove_fixture_app_credentials(self):
        # Exact disposable target only. Cleanup after a failed positive preserves the failure
        # while preventing real fixture app/mail MFA from changing later login preconditions.
        for credential in self.admin("GET", "/users/" + self.account_id + "/credentials"):
            if credential["type"] in {"otp", "MAIL_OTP_CM"}:
                self.admin("DELETE", "/users/" + self.account_id + "/credentials/" + credential["id"])

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

    def scoped_read(self, human, target, expected, actor="ACCOUNT_ADMIN", mutate=False, bearer=None):
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
            "Authorization": "Bearer " + (self.token(actor) if bearer is None else bearer),
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
        return self.scoped_mutation(human, body, "otp.app-setup", "PUT", "setup-otp", 201)

    def scoped_mutation(self, human, body, operation, method, route, expected, actor="ACCOUNT_ADMIN", bearer=None):
        username = self.creation_input["account"]["username"]
        materialized = {**body, "username": username}
        now = int(time.time())
        claims = {
            "iss": "userservice", "aud": "oriso-otp", "purpose": "OTP",
            "operation": operation, "method": method, "actor": actor,
            "realm": REALM,
            "target": "realm/" + self.realm_id + "/account/" + self.account_id,
            "taskClient": ACTORS[actor][0], "taskSubject": SUBJECTS[actor],
            "payloadDigest": mac("payload", materialized), "jti": str(uuid.uuid4()),
            "nonce": uuid.uuid4().hex, "iat": now, "exp": now + 60,
        }
        encoded = base64.urlsafe_b64encode(canonical(claims)).decode().rstrip("=")
        signature = base64.urlsafe_b64encode(hmac.new(
            CONTEXT_KEY, ("proof\n" + encoded).encode(), hashlib.sha256).digest()).decode().rstrip("=")
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + (self.token(actor) if bearer is None else bearer),
            "X-ORISO-Task-Context": encoded + "." + signature,
        }
        if human is not None:
            headers["X-ORISO-Human-Authorization"] = "Bearer " + human
        request = Request(
            self.base + "/realms/" + REALM + "/otp-config/" + route + "/" + quote(username, safe=""),
            data=canonical(body), method=method, headers=headers,
        )
        try:
            with urlopen(request, timeout=30) as response:
                status, raw = response.status, response.read()
        except HTTPError as error:
            status, raw = error.code, error.read()
            error.close()
        phase = {"otp.app-setup": "scoped-otp-app-setup-http",
                 "otp.delete": "scoped-otp-delete-http",
                 "otp.email-finish": "scoped-otp-email-finish-http"}[operation]
        self.phase(phase, status=status, expected_status=expected)
        return status, json.loads(raw) if raw else None

    def canonical_admin_with_one_extra_audience(self):
        canonical_bearer = self.token("ACCOUNT_ADMIN")
        def claims(token):
            encoded = token.split(".")[1]
            return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        original = claims(canonical_bearer)
        expected = {"userservice", "oriso-account-lifecycle", "oriso-otp"}
        self.assertEqual(expected, set(original["aud"]))
        clients = self.admin("GET", "/clients?clientId=" + ACTORS["ACCOUNT_ADMIN"][0])
        self.assertEqual(1, len(clients))
        path = "/clients/" + clients[0]["id"] + "/protocol-mappers/models"
        before = self.admin("GET", path)
        name = "fixture-extra-audience-" + uuid.uuid4().hex
        self.admin("POST", path, {"name": name, "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
            "config": {"included.custom.audience": "realm-management",
                       "access.token.claim": "true", "id.token.claim": "false"}})
        matching = [mapper for mapper in self.admin("GET", path) if mapper["name"] == name]
        self.assertEqual(1, len(matching))
        try:
            extra_bearer = self.token("ACCOUNT_ADMIN")
        finally:
            self.admin("DELETE", path + "/" + matching[0]["id"])
        self.assertEqual(sorted(before, key=lambda x: x["id"]),
                         sorted(self.admin("GET", path), key=lambda x: x["id"]))
        extra = claims(extra_bearer)
        self.assertEqual(expected | {"realm-management"}, set(extra["aud"]))
        for field in ["iss", "sub", "azp", "realm_access", "resource_access"]:
            self.assertEqual(original.get(field), extra.get(field))
        self.assertEqual(expected, set(claims(self.token("ACCOUNT_ADMIN"))["aud"]))
        self.phase("scoped-otp-extra-audience-native-token", exact_original_three=True,
                   exact_extra_four=True, actual_same_subject_client_issuer_roles=True,
                   client_restored_before_request=True)
        return extra_bearer

    def test_canonical_admin_with_only_one_extra_audience_cannot_read_or_mutate(self):
        human, target = self.human(), self.target()
        body = self.app_enrollment_body(human, target)
        extra = self.canonical_admin_with_one_extra_audience()
        self.assertEqual(403, self.scoped_read(human, target, 403, bearer=extra)[0])
        before = self.admin("GET", "/users/" + self.account_id + "/credentials")
        self.assertEqual(403, self.scoped_mutation(human, body, "otp.app-setup", "PUT",
                                                  "setup-otp", 403, bearer=extra)[0])
        self.assertEqual(before, self.admin("GET", "/users/" + self.account_id + "/credentials"))
        self.assertEqual(201, self.scoped_app_setup(human, body)[0])
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        delete = {"target": target, "operationId": str(uuid.uuid4()),
                  "expectedState": current["state"], "otp": None}
        self.assertEqual(403, self.scoped_mutation(human, delete, "otp.delete", "DELETE",
                                                  "delete-otp", 403, bearer=extra)[0])
        self.assertTrue(self.scoped_read(human, target, 200)[1]["otpSetup"])
        self.assertEqual(200, self.scoped_mutation(human, delete, "otp.delete", "DELETE",
                                                  "delete-otp", 200)[0])
        self.phase("scoped-otp-extra-audience-current-routes", exact_three_read_app_delete_positive=True,
                   extra_four_read_app_delete_denied=True, denied_calls_without_effect=True)

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

    def test_invalid_app_code_commits_terminal_receipt_before_later_native_state_changes(self):
        import struct
        human, target = self.human(), self.target()
        body = self.app_enrollment_body(human, target)
        realm = self.admin("GET", "")
        self.assertEqual("HmacSHA1", realm["otpPolicyAlgorithm"])
        self.assertEqual(6, realm["otpPolicyDigits"])
        self.assertEqual(30, realm["otpPolicyPeriod"])
        window = realm["otpPolicyLookAheadWindow"]
        self.assertTrue(isinstance(window, int) and 0 <= window <= 10)
        excluded = set()
        for step in range(-window - 1, window + 2):
            digest = hmac.new(body["otp"]["secret"].encode(), struct.pack(
                ">Q", int(time.time()) // 30 + step), hashlib.sha1).digest()
            offset = digest[-1] & 15
            excluded.add(str((struct.unpack(">I", digest[offset:offset + 4])[0]
                              & 0x7FFFFFFF) % 1000000).zfill(6))
        body["otp"]["initialCode"] = next(str(number).zfill(6) for number in range(100)
                                             if str(number).zfill(6) not in excluded)
        status, refused = self.scoped_mutation(human, body, "otp.app-setup", "PUT", "setup-otp", 401)
        self.assertEqual(401, status)
        self.assertEqual(401, refused["status"])
        self.assertEqual("invalid_grant", refused["result"]["error"])
        encoded, signature = refused["receipt"].split(".")
        expected = hmac.new(CONTEXT_KEY, ("otp-operation-receipt\n" + encoded).encode(), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(expected, signature))
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(401, payload["status"])
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], payload["ownerSubject"])
        native = self.admin("GET", "/users/" + self.account_id)
        attributes = dict(native["attributes"])
        attributes["locale"] = ["it" if attributes.get("locale") == ["fr"] else "fr"]
        self.replace_native_attributes(attributes)
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        self.assertNotEqual(body["expectedState"], current["state"])
        status, retried = self.scoped_mutation(human, body, "otp.app-setup", "PUT", "setup-otp", 401)
        self.assertEqual(401, status)
        self.assertEqual(refused, retried)
        self.assertFalse(self.scoped_read(human, target, 200)[1]["otpSetup"])
        self.phase("scoped-otp-app-terminal-refusal", native_receipt_verified=True,
                   saved_receipt_equal=True, returned_before_changed_cas=True, no_enrollment=True)

    def test_app_mutation_checks_origin_actor_session_and_fresh_state_before_effect(self):
        human, target = self.human(), self.target()
        body = self.app_enrollment_body(human, target)
        mixed = json.loads(json.dumps(body))
        mixed["target"]["origin"]["humanIssuer"] = "https://foreign.invalid/realms/other"
        self.assertEqual(403, self.scoped_mutation(human, mixed, "otp.app-setup", "PUT", "setup-otp", 403)[0])
        self.assertEqual(403, self.scoped_mutation(human, body, "otp.app-setup", "PUT", "setup-otp", 403,
                                                 actor="ACCOUNT_CREATE")[0])
        self.assertEqual(401, self.scoped_mutation(None, body, "otp.app-setup", "PUT", "setup-otp", 401)[0])
        stale = json.loads(json.dumps(body))
        stale["expectedState"] = "0" * 64 if body["expectedState"] != "0" * 64 else "1" * 64
        self.assertEqual(409, self.scoped_mutation(human, stale, "otp.app-setup", "PUT", "setup-otp", 409)[0])
        self.assertFalse(self.scoped_read(human, target, 200)[1]["otpSetup"])
        self.phase("scoped-otp-app-denials", origin_mix_denied=True, create_actor_denied=True,
                   missing_human_denied=True, stale_cas_denied=True, no_enrollment=True)

    def app_enrollment_body(self, human, target):
        import struct
        status, setup = self.scoped_read(human, target, 200)
        self.assertEqual(200, status)
        self.assertFalse(setup["otpSetup"])
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        seed = setup["otpSecret"]
        digest = hmac.new(seed.encode(), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
        offset = digest[-1] & 15
        code = str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)
        return {"target": target, "operationId": str(uuid.uuid4()), "expectedState": current["state"],
                "otp": {"initialCode": code, "secret": seed, "email": None}}

    def test_current_self_delete_retry_never_removes_a_later_enrollment(self):
        human, target = self.human(), self.target()
        self.assertEqual(201, self.scoped_app_setup(human, self.app_enrollment_body(human, target))[0])
        self.assertEqual(1, len([c for c in self.admin("GET", "/users/" + self.account_id
                                                     + "/credentials") if c["type"] == "otp"]))
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        self.assertEqual(403, call(self.base, "GET", "/admin/realms/" + REALM
                                  + "/users/" + self.account_id, token=self.token("ACCOUNT_ADMIN"))[0])
        body = {"target": target, "operationId": str(uuid.uuid4()),
                "expectedState": current["state"], "otp": None}
        self.phase("scoped-otp-delete-preconditions", canonical_admin=True, stock_native_denied=True,
                   actual_self_human=True, committed_ordinary_target=True,
                   actual_prior_scoped_enrollment=True, frozen_current_state=True)
        status, deleted = self.scoped_mutation(human, body, "otp.delete", "DELETE", "delete-otp", 200)
        self.assertEqual(200, status)
        self.assertEqual(200, deleted["status"])
        self.assertEqual(body["operationId"], deleted["operationId"])
        self.assertFalse(self.scoped_read(human, target, 200)[1]["otpSetup"])
        self.assertEqual(201, self.scoped_app_setup(human, self.app_enrollment_body(human, target))[0])
        status, retried = self.scoped_mutation(human, body, "otp.delete", "DELETE", "delete-otp", 200)
        self.assertEqual(200, status)
        self.assertEqual(deleted, retried)
        self.assertTrue(self.scoped_read(human, target, 200)[1]["otpSetup"])
        self.phase("scoped-otp-delete-exact-retry", saved_receipt_equal=True, no_redelete=True)

    def seed_pending_email_credential(self, code, email="pending@fixture.invalid", expiry_offset_ms=600000):
        before = self.admin("GET", "/users/" + self.account_id)
        existing = self.admin("GET", "/users/" + self.account_id + "/credentials")
        self.assertFalse(any(c["type"] in {"otp", "MAIL_OTP_CM"} for c in existing))
        credential_id = str(uuid.uuid4())
        now = int(time.time() * 1000)
        pending = {"id": credential_id, "type": "MAIL_OTP_CM", "createdDate": now,
                   "credentialData": canonical({"ttlInSeconds": 600, "email": email,
                       "failedVerifications": 0, "active": False, "mailsSentAt": [],
                       "lockedUntil": None, "lockoutLevel": 0}).decode(),
                   "secretData": canonical({"code": code, "expiry": now + expiry_offset_ms}).decode()}
        updated = dict(before)
        updated["credentials"] = [pending]
        status, _ = call(self.base, "PUT", "/admin/realms/" + REALM + "/users/" + self.account_id,
                         updated, token=self.installer)
        self.phase("scoped-otp-email-fixture-seed-write", status=status)
        self.assertEqual(204, status)
        self.addCleanup(self.remove_exact_mail_seed, credential_id)
        after = self.admin("GET", "/users/" + self.account_id)
        self.phase("scoped-otp-email-fixture-profile-read", completed=True)
        for field in ["id", "username", "email", "firstName", "lastName", "enabled", "attributes", "requiredActions"]:
            self.assertEqual(before.get(field), after.get(field))
        self.phase("scoped-otp-email-fixture-profile-preserved", completed=True)
        status, credentials = call(self.base, "GET", "/admin/realms/" + REALM + "/users/"
                                   + self.account_id + "/credentials", token=self.installer)
        self.phase("scoped-otp-email-fixture-credentials-read", status=status)
        self.assertEqual(200, status)
        mail = [c for c in credentials if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual(1, len(mail))
        self.assertEqual(credential_id, mail[0]["id"])
        self.assertFalse(json.loads(mail[0]["credentialData"])["active"])
        self.assertEqual(0, json.loads(mail[0]["credentialData"])["failedVerifications"])
        self.assertEqual(email, json.loads(mail[0]["credentialData"])["email"])
        return credential_id

    def test_current_self_finishes_exact_native_pending_email_credential(self):
        human, target = self.human(), self.target()
        code = "937451"
        credential_id = self.seed_pending_email_credential(code)
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        self.assertEqual(403, call(self.base, "GET", "/admin/realms/" + REALM
                                  + "/users/" + self.account_id, token=self.token("ACCOUNT_ADMIN"))[0])
        body = {"target": target, "operationId": str(uuid.uuid4()),
                "expectedState": current["state"],
                "otp": {"initialCode": code, "secret": None, "email": None}}
        self.phase("scoped-otp-email-finish-preconditions", canonical_admin=True,
                   stock_native_denied=True, actual_self_human=True, committed_ordinary_target=True,
                   installer_owned_pending_fixture=True, exact_one_inactive_native_credential=True,
                   frozen_current_state=True, reviewed_email_finish_selector=True)
        extra = self.canonical_admin_with_one_extra_audience()
        self.assertEqual(403, self.scoped_mutation(human, body, "otp.email-finish", "POST",
                                                  "setup-otp-mail", 403, bearer=extra)[0])
        status, result = self.scoped_mutation(human, body, "otp.email-finish", "POST", "setup-otp-mail", 201)
        self.assertEqual(201, status)
        self.assertEqual(201, result["status"])
        self.assertEqual(body["operationId"], result["operationId"])
        self.assertEqual({"info": "OTP setup created"}, result["result"])
        encoded, signature = result["receipt"].split(".")
        expected = hmac.new(CONTEXT_KEY, ("otp-operation-receipt\n" + encoded).encode(), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(expected, signature))
        receipt = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(ACTORS["ACCOUNT_ADMIN"][0], receipt["ownerClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], receipt["ownerSubject"])
        self.assertEqual("otp.email-finish", receipt["operation"])
        binding = receipt["emailCredential"]
        self.assertEqual({"credentialId", "generation", "destinationDigest"}, set(binding))
        self.assertEqual(credential_id, binding["credentialId"])
        self.assertRegex(binding["generation"], r"^[a-f0-9]{64}$")
        destination = hmac.new(CONTEXT_KEY, b"otp-email-destination\n" + canonical("pending@fixture.invalid"), hashlib.sha256).hexdigest()
        self.assertEqual(destination, binding["destinationDigest"])
        serialized = canonical(result) + canonical(receipt)
        self.assertNotIn(b"pending@fixture.invalid", serialized)
        self.assertNotIn(canonical(code), serialized)
        mail = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials")
                if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual(1, len(mail))
        self.assertEqual(credential_id, mail[0]["id"])
        self.assertTrue(json.loads(mail[0]["credentialData"])["active"])
        self.phase("scoped-otp-email-finish-effect", exact_native_credential_activated=True,
                   actual_admin_receipt=True, credential_generation_destination_bound=True,
                   plaintext_recipient_code_absent=True, exact_three_to_four_only_denial=True)
        self.admin("DELETE", "/users/" + self.account_id + "/credentials/" + credential_id)
        later = self.seed_pending_email_credential("628593", "later@fixture.invalid")
        status, retried = self.scoped_mutation(human, body, "otp.email-finish", "POST", "setup-otp-mail", 201)
        self.assertEqual(201, status)
        self.assertEqual(result, retried)
        mail = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials")
                if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual([later], [c["id"] for c in mail])
        self.assertFalse(json.loads(mail[0]["credentialData"])["active"])
        self.assertEqual(0, json.loads(mail[0]["credentialData"])["failedVerifications"])
        self.phase("scoped-otp-email-finish-exact-retry", saved_receipt_equal=True,
                   later_generation_recipient_preserved=True, no_second_activation=True)

    def test_invalid_email_code_commits_one_terminal_attempt_and_cached_retry(self):
        human, target = self.human(), self.target()
        credential_id = self.seed_pending_email_credential("937451")
        bearer = self.token("ACCOUNT_ADMIN")
        encoded = bearer.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual({"userservice", "oriso-account-lifecycle", "oriso-otp"}, set(claims["aud"]))
        self.assertEqual(403, call(self.base, "GET", "/admin/realms/" + REALM
                                  + "/users/" + self.account_id, token=bearer)[0])
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        body = {"target": target, "operationId": str(uuid.uuid4()),
                "expectedState": current["state"],
                "otp": {"initialCode": "000001", "secret": None, "email": None}}
        self.phase("scoped-otp-email-invalid-preconditions", canonical_admin=True,
                   stock_native_denied=True, actual_self_human=True, committed_ordinary_target=True,
                   exact_one_live_inactive_native_credential=True, initial_attempt_count_zero=True,
                   actual_wrong_code=True, frozen_current_state=True)
        status, result = self.scoped_mutation(human, body, "otp.email-finish", "POST", "setup-otp-mail", 401)
        self.assertEqual(401, status)
        self.assertEqual(401, result["status"])
        self.assertEqual(body["operationId"], result["operationId"])
        self.assertEqual({"error": "invalid_grant", "error_description": "Invalid code"}, result["result"])
        encoded, signature = result["receipt"].split(".")
        expected = hmac.new(CONTEXT_KEY, ("otp-operation-receipt\n" + encoded).encode(), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(expected, signature))
        receipt = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(ACTORS["ACCOUNT_ADMIN"][0], receipt["ownerClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], receipt["ownerSubject"])
        self.assertEqual(401, receipt["status"])
        self.assertEqual(credential_id, receipt["emailCredential"]["credentialId"])
        mail = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials")
                if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual([credential_id], [c["id"] for c in mail])
        self.assertFalse(json.loads(mail[0]["credentialData"])["active"])
        self.assertEqual(1, json.loads(mail[0]["credentialData"])["failedVerifications"])
        self.phase("scoped-otp-email-invalid-terminal", one_native_attempt_committed=True,
                   immutable_actual_admin_terminal_receipt=True, no_activation=True)
        self.admin("DELETE", "/users/" + self.account_id + "/credentials/" + credential_id)
        later = self.seed_pending_email_credential("628593", "later@fixture.invalid")
        status, retried = self.scoped_mutation(human, body, "otp.email-finish", "POST", "setup-otp-mail", 401)
        self.assertEqual(401, status)
        self.assertEqual(result, retried)
        mail = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials")
                if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual([later], [c["id"] for c in mail])
        self.assertFalse(json.loads(mail[0]["credentialData"])["active"])
        self.assertEqual(0, json.loads(mail[0]["credentialData"])["failedVerifications"])
        self.phase("scoped-otp-email-invalid-exact-retry", saved_receipt_equal=True,
                   later_generation_preserved=True, no_second_attempt=True)

    def test_expired_email_code_commits_one_terminal_attempt_and_cached_retry(self):
        human, target = self.human(), self.target()
        credential_id = self.seed_pending_email_credential("937451", expiry_offset_ms=-60000)
        bearer = self.token("ACCOUNT_ADMIN")
        encoded = bearer.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual({"userservice", "oriso-account-lifecycle", "oriso-otp"}, set(claims["aud"]))
        self.assertEqual(403, call(self.base, "GET", "/admin/realms/" + REALM
                                  + "/users/" + self.account_id, token=bearer)[0])
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        body = {"target": target, "operationId": str(uuid.uuid4()),
                "expectedState": current["state"],
                "otp": {"initialCode": "937451", "secret": None, "email": None}}
        self.phase("scoped-otp-email-expired-preconditions", canonical_admin=True,
                   stock_native_denied=True, actual_self_human=True, committed_ordinary_target=True,
                   exact_one_live_inactive_native_credential=True, initial_attempt_count_zero=True,
                   installer_imported_expiry_past=True, matching_original_code=True, frozen_current_state=True)
        status, result = self.scoped_mutation(human, body, "otp.email-finish", "POST", "setup-otp-mail", 401)
        self.assertEqual(401, status)
        self.assertEqual(401, result["status"])
        self.assertEqual(body["operationId"], result["operationId"])
        self.assertEqual({"error": "invalid_grant", "error_description": "Code expired"}, result["result"])
        encoded, signature = result["receipt"].split(".")
        expected = hmac.new(CONTEXT_KEY, ("otp-operation-receipt\n" + encoded).encode(), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(expected, signature))
        receipt = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(ACTORS["ACCOUNT_ADMIN"][0], receipt["ownerClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], receipt["ownerSubject"])
        self.assertEqual(401, receipt["status"])
        self.assertEqual(credential_id, receipt["emailCredential"]["credentialId"])
        mail = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials")
                if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual([credential_id], [c["id"] for c in mail])
        self.assertFalse(json.loads(mail[0]["credentialData"])["active"])
        self.assertEqual(1, json.loads(mail[0]["credentialData"])["failedVerifications"])
        self.phase("scoped-otp-email-expired-terminal", one_native_attempt_committed=True,
                   immutable_actual_admin_terminal_receipt=True, no_activation=True)
        self.admin("DELETE", "/users/" + self.account_id + "/credentials/" + credential_id)
        later = self.seed_pending_email_credential("628593", "later@fixture.invalid")
        status, retried = self.scoped_mutation(human, body, "otp.email-finish", "POST", "setup-otp-mail", 401)
        self.assertEqual(401, status)
        self.assertEqual(result, retried)
        mail = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials")
                if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual([later], [c["id"] for c in mail])
        self.assertFalse(json.loads(mail[0]["credentialData"])["active"])
        self.assertEqual(0, json.loads(mail[0]["credentialData"])["failedVerifications"])
        self.phase("scoped-otp-email-expired-exact-retry", saved_receipt_equal=True,
                   later_generation_preserved=True, no_second_attempt=True)

    def remove_exact_mail_seed(self, credential_id):
        status, _ = call(self.base, "DELETE", "/admin/realms/" + REALM + "/users/"
                         + self.account_id + "/credentials/" + credential_id, token=self.installer)
        self.phase("scoped-otp-email-fixture-exact-cleanup", status=status)
        self.assertIn(status, (204, 404))

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
