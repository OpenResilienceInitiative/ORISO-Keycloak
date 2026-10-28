"""Original OTP GET under actual canonical ADMIN and current native ordinary SELF."""

import base64
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import time
import threading
import unittest
import uuid
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

from lifecycle_fixture import ACTORS, CONTEXT_KEY, REALM, SUBJECTS, call, canonical, mac
from maintenance_human_fixture import CLIENT, ISSUER, HumanMaintenanceFixture


class ScopedOtpRead(HumanMaintenanceFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use the same private, synthetic SMTP sink as the retained original-route fixture.
        source = Path(__file__).resolve().parents[2] / "otp-config-spi/tests/scenario_c_otp_fixture.py"
        spec = importlib.util.spec_from_file_location("scoped_otp_mail_fixture", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.mail = module.MailSink(("0.0.0.0", 0), module.MailSink.Handler)
        cls.mail.messages = []
        cls.addClassCleanup(cls.mail.server_close)
        cls.addClassCleanup(cls.mail.shutdown)
        threading.Thread(target=cls.mail.serve_forever, daemon=True).start()
        super().setUpClass()

    @classmethod
    def extra_launch_arguments(cls):
        jar = Path(os.environ.get("OTP_C_TEST_JAR", ""))
        if not jar.is_file():
            raise AssertionError("Actual compiled OTP provider is required")
        fixture = Path(os.environ.get("SCOPED_OTP_READY_FIXTURE_JAR", ""))
        if not fixture.is_file():
            raise AssertionError("Separately built READY completion fixture is required")
        return [
            "-v", str(fixture.resolve()) + ":/opt/keycloak/providers/scoped-otp-ready-fixture.jar:ro",
            "-v", str(jar.resolve()) + ":/opt/keycloak/providers/otp-config-spi.jar:ro",
            "-e", "IDENTITY_ACCOUNT_ADMIN_CLIENT_ID=backend-account-admin",
            "-e", "ORISO_APP_BASE_URL=https://otp-fixture.internal",
            "-e", "EMAIL_BRANDING_NAME=OTP Fixture",
            "-e", "EMAIL_LEGAL_ORGANISATION_NAME=Fixture Operator",
            "-v", str(Path(__file__).resolve().parents[2] / "themes/oriso") + ":/opt/keycloak/themes/oriso:ro",
            "--add-host", "host.docker.internal:host-gateway",
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
                self.last_response_no_store = "no-store" in response.headers.get("Cache-Control", "")
        except HTTPError as error:
            status, raw = error.code, error.read()
            self.last_response_no_store = "no-store" in error.headers.get("Cache-Control", "")
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

    def scoped_mutation(self, human, body, operation, method, route, expected, actor="ACCOUNT_ADMIN", bearer=None, fixture_operation=None):
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
        if fixture_operation is not None:
            headers["X-ORISO-Ready-Fixture"] = fixture_operation
        if human is not None:
            headers["X-ORISO-Human-Authorization"] = "Bearer " + human
        request = Request(
            self.base + "/realms/" + REALM + "/otp-config/" + route + "/" + quote(username, safe=""),
            data=canonical(body), method=method, headers=headers,
        )
        observation_headers = {"State", "Tx", "Revoked", "Expired"}
        try:
            with urlopen(request, timeout=30) as response:
                status, raw = response.status, response.read()
                self._ready_observation = {key: response.headers.get("X-ORISO-Ready-Fixture-" + key) for key in observation_headers}
        except HTTPError as error:
            status, raw = error.code, error.read()
            self._ready_observation = {key: error.headers.get("X-ORISO-Ready-Fixture-" + key) for key in observation_headers}
            error.close()
        phase = {"otp.app-setup": "scoped-otp-app-setup-http",
                 "otp.delete": "scoped-otp-delete-http",
                 "otp.email-finish": "scoped-otp-email-finish-http",
                 "otp.email-start": "scoped-otp-email-start-http",
                 "otp.email-start-outcome": "scoped-otp-email-outcome-http"}[operation]
        self.phase(phase, status=status, expected_status=expected)
        return status, json.loads(raw) if raw else None

    def test_current_self_email_start_uses_foreground_delivery_and_exact_retry_never_resends(self):
        human, target = self.human(), self.target()
        realm = self.admin("GET", "")
        realm["emailTheme"] = "oriso"
        realm["smtpServer"] = {
            "host": "host.docker.internal", "port": str(self.mail.server_address[1]),
            "from": "otp-fixture@oriso.org", "auth": "false", "ssl": "false",
            "starttls": "false",
        }
        self.admin("PUT", "", realm)
        self.assertEqual(realm["smtpServer"], self.admin("GET", "")["smtpServer"])
        self.assertFalse(any(c["type"] in {"otp", "MAIL_OTP_CM"}
                             for c in self.admin("GET", "/users/" + self.account_id + "/credentials")))
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        bearer = self.token("ACCOUNT_ADMIN")
        encoded = bearer.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual({"userservice", "oriso-account-lifecycle", "oriso-otp"}, set(claims["aud"]))
        self.assertEqual(403, call(self.base, "GET", "/admin/realms/" + REALM
                                  + "/users/" + self.account_id, token=bearer)[0])
        before_mail = len(self.mail.messages)
        original_deadline = int(time.time()) + 180
        self.assertLess(original_deadline, claims["exp"])
        body = {"target": target, "operationId": str(uuid.uuid4()),
                "expectedState": current["state"], "authorityValidUntil": original_deadline,
                "otp": {"initialCode": None, "secret": None,
                        "email": "pending-" + uuid.uuid4().hex + "@oriso.org"}}
        self.phase("scoped-otp-email-start-preconditions", canonical_admin=True,
                   exact_three_audiences=True, stock_native_denied=True, actual_self_human=True,
                   committed_ordinary_target=True, frozen_current_state=True,
                   no_prior_otp=True, real_smtp_configured=True, reviewed_email_start_selector=True)
        status, prepared = self.scoped_mutation(human, body, "otp.email-start", "PUT",
                                               "send-verification-mail", 202, bearer=bearer)
        self.assertEqual(202, status)
        self.assertEqual(body["operationId"], prepared["operationId"])
        self.assertEqual("READY", prepared["deliveryState"])
        # The response is prepared before request completion. Reauthenticated exact-intent
        # recovery observes its durable final result instead of changing that old response.
        status, delivered = self.scoped_mutation(human, body, "otp.email-start", "PUT",
                                                "send-verification-mail", 200)
        self.assertEqual(200, status)
        self.assertEqual("SENT", delivered["deliveryState"])
        self.assertEqual(body["operationId"], delivered["operationId"])
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        current = self.admin("GET", "/users/" + self.account_id + "/credentials")
        owned = [c for c in current if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual(1, len(owned))
        self.assertFalse(json.loads(owned[0]["credentialData"])["active"])
        encoded, signature = delivered["receipt"].split(".")
        expected = hmac.new(CONTEXT_KEY, ("otp-operation-receipt\n" + encoded).encode(), hashlib.sha256).hexdigest()
        self.assertTrue(hmac.compare_digest(expected, signature))
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], payload["ownerSubject"])
        self.assertEqual("otp.email-start", payload["operation"])
        self.assertLessEqual(payload["authorityValidUntil"], original_deadline)
        self.assertNotIn(body["otp"]["email"], canonical(delivered).decode())
        self.assertEqual(delivered, self.scoped_mutation(human, body, "otp.email-start", "PUT",
                                                        "send-verification-mail", 200)[1])
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        self.assertEqual(owned, [c for c in self.admin("GET", "/users/" + self.account_id
                                                     + "/credentials") if c["type"] == "MAIL_OTP_CM"])
        extra = self.canonical_admin_with_one_extra_audience()
        self.assertEqual(403, self.scoped_mutation(human, body, "otp.email-start", "PUT",
                                                  "send-verification-mail", 403, bearer=extra)[0])
        self.assertEqual(401, self.scoped_mutation(None, body, "otp.email-start", "PUT",
                                                  "send-verification-mail", 401)[0])
        changed = json.loads(json.dumps(body))
        changed["otp"]["email"] = "changed@oriso.org"
        self.assertEqual(409, self.scoped_mutation(human, changed, "otp.email-start", "PUT",
                                                  "send-verification-mail", 409)[0])
        mixed = json.loads(json.dumps(body))
        mixed["target"]["origin"]["humanIssuer"] = "https://foreign.invalid/realms/other"
        mixed["operationId"] = str(uuid.uuid4())
        self.assertEqual(403, self.scoped_mutation(human, mixed, "otp.email-start", "PUT",
                                                  "send-verification-mail", 403)[0])
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        self.phase("scoped-otp-email-start-exact-retry", one_smtp_effect=True,
                   one_owned_inactive_credential=True, immutable_final_receipt=True,
                   no_plaintext_destination_in_public_result=True, no_resend=True)

    def test_current_self_linked_email_finish_updates_only_committed_sent_destination(self):
        from email import policy as email_policy
        from email.parser import BytesParser
        import re
        human, start_target = self.human(), self.target()
        realm = self.admin("GET", "")
        realm["emailTheme"] = "oriso"
        realm["smtpServer"] = {"host": "host.docker.internal", "port": str(self.mail.server_address[1]),
                               "from": "otp-fixture@oriso.org", "auth": "false", "ssl": "false", "starttls": "false"}
        self.admin("PUT", "", realm)
        before_mail = len(self.mail.messages)
        destination = "linked-" + uuid.uuid4().hex + "@oriso.org"
        body = self.email_start_body(human, start_target, destination)
        self.assertEqual(202, self.scoped_mutation(human, body, "otp.email-start", "PUT",
                                                  "send-verification-mail", 202)[0])
        status, delivered = self.scoped_mutation(human, body, "otp.email-start", "PUT",
                                                 "send-verification-mail", 200)
        self.assertEqual(200, status)
        self.assertEqual("SENT", delivered["deliveryState"])
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        message = BytesParser(policy=email_policy.default).parsebytes(self.mail.messages[-1])
        codes = set()
        for part in message.walk():
            if part.get_content_type() in {"text/plain", "text/html"}:
                text = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
                codes.update(re.findall(r"(?<![0-9])[0-9]{6}(?![0-9])", text))
        self.assertEqual(1, len(codes), "Exactly one actual delivered native OTP is required")
        target = self.target()
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        self.assertNotEqual(destination, self.admin("GET", "/users/" + self.account_id).get("email"))
        self.assertEqual(403, call(self.base, "GET", "/admin/realms/" + REALM + "/users/" + self.account_id,
                                  token=self.token("ACCOUNT_ADMIN"))[0])
        finish = {"target": target, "operationId": str(uuid.uuid4()), "expectedState": current["state"],
                  "emailStartOperationId": body["operationId"],
                  "otp": {"initialCode": next(iter(codes)), "secret": None, "email": None}}
        self.phase("scoped-otp-linked-email-finish-preconditions", canonical_admin=True,
                   stock_native_denied=True, actual_self_human=True, committed_ordinary_target=True,
                   actual_committed_sent_workflow=True, actual_one_smtp=True,
                   exact_delivered_code=True, frozen_current_state=True, native_email_not_yet_changed=True)
        status, result = self.scoped_mutation(human, finish, "otp.email-finish", "POST", "setup-otp-mail", 201)
        self.assertEqual(201, status)
        current_user = self.admin("GET", "/users/" + self.account_id)
        self.assertEqual(destination, current_user["email"])
        self.assertTrue(current_user["emailVerified"])
        encoded, signature = result["receipt"].split(".")
        self.assertTrue(hmac.compare_digest(hmac.new(CONTEXT_KEY, ("otp-operation-receipt\n" + encoded).encode(), hashlib.sha256).hexdigest(), signature))
        receipt = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(body["operationId"], receipt["emailStartOperationId"])
        self.assertEqual("otp.email-finish", receipt["operation"])
        self.assertNotIn(destination, canonical(result).decode())
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        current_user["email"] = "later-" + uuid.uuid4().hex + "@oriso.org"
        self.admin("PUT", "/users/" + self.account_id, current_user)
        self.assertEqual(result, self.scoped_mutation(human, finish, "otp.email-finish", "POST", "setup-otp-mail", 201)[1])
        self.assertEqual(current_user["email"], self.admin("GET", "/users/" + self.account_id)["email"])
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        self.phase("scoped-otp-linked-email-finish-effect", native_email_and_verified=True,
                   exact_sent_workflow_receipt=True, one_smtp=True, exact_retry_no_reapplication=True)

    def linked_finish_fixture(self, deadline_seconds=120):
        from email import policy as email_policy
        from email.parser import BytesParser
        import re
        human, start_target = self.human(), self.target()
        realm = self.admin("GET", "")
        realm["emailTheme"] = "oriso"
        realm["smtpServer"] = {"host": "host.docker.internal", "port": str(self.mail.server_address[1]),
                               "from": "otp-fixture@oriso.org", "auth": "false", "ssl": "false", "starttls": "false"}
        self.admin("PUT", "", realm)
        before_mail = len(self.mail.messages)
        destination = "linked-controls-" + uuid.uuid4().hex + "@oriso.org"
        start = self.email_start_body(human, start_target, destination)
        start["authorityValidUntil"] = int(time.time()) + deadline_seconds
        self.assertEqual(202, self.scoped_mutation(human, start, "otp.email-start", "PUT", "send-verification-mail", 202)[0])
        status, sent = self.scoped_mutation(human, start, "otp.email-start", "PUT", "send-verification-mail", 200)
        self.assertEqual(200, status)
        self.assertEqual("SENT", sent["deliveryState"])
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        message = BytesParser(policy=email_policy.default).parsebytes(self.mail.messages[-1])
        codes = set()
        for part in message.walk():
            if part.get_content_type() in {"text/plain", "text/html"}:
                text = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
                codes.update(re.findall(r"(?<![0-9])[0-9]{6}(?![0-9])", text))
        self.assertEqual(1, len(codes), "One actual native delivered code is required")
        target = self.target()
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        self.assertEqual(403, call(self.base, "GET", "/admin/realms/" + REALM + "/users/" + self.account_id,
                                  token=self.token("ACCOUNT_ADMIN"))[0])
        original = self.admin("GET", "/users/" + self.account_id).get("email")
        self.assertNotEqual(destination, original)
        finish = {"target": target, "operationId": str(uuid.uuid4()), "expectedState": current["state"],
                  "emailStartOperationId": start["operationId"],
                  "otp": {"initialCode": next(iter(codes)), "secret": None, "email": None}}
        self._last_delivered_start = start
        self._last_sent_result = sent
        return human, finish, destination, original, before_mail

    def test_linked_email_invalid_attempt_then_new_intent_activates_same_owned_incarnation(self):
        human, finish, destination, original, before_mail = self.linked_finish_fixture()
        invalid = json.loads(json.dumps(finish))
        code = invalid["otp"]["initialCode"]
        invalid["otp"]["initialCode"] = str((int(code) + 1) % 1000000).zfill(6)
        status, refused = self.scoped_mutation(human, invalid, "otp.email-finish", "POST", "setup-otp-mail", 401)
        self.assertEqual(401, status)
        self.assertEqual(refused, self.scoped_mutation(human, invalid, "otp.email-finish", "POST", "setup-otp-mail", 401)[1])
        mail = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials") if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual(1, len(mail))
        self.assertEqual(1, json.loads(mail[0]["credentialData"])["failedVerifications"])
        self.assertFalse(json.loads(mail[0]["credentialData"])["active"])
        self.assertEqual(original, self.admin("GET", "/users/" + self.account_id).get("email"))
        finish["operationId"] = str(uuid.uuid4())
        finish["expectedState"] = self.invoke("read", {"target": finish["target"]}, human, 200)[1]["state"]
        status, result = self.scoped_mutation(human, finish, "otp.email-finish", "POST", "setup-otp-mail", 201)
        self.assertEqual(201, status)
        self.assertEqual(destination, self.admin("GET", "/users/" + self.account_id).get("email"))
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        self.phase("scoped-otp-linked-invalid-new-intent", one_failed_attempt=True,
                   cached_refusal=True, same_owned_incarnation=True, new_valid_intent=True, no_resend=True)

    def test_linked_email_foreign_reference_and_origin_refuse_without_attempt_or_profile_effect(self):
        human, finish, destination, original, before_mail = self.linked_finish_fixture()
        foreign = json.loads(json.dumps(finish))
        foreign["emailStartOperationId"] = str(uuid.uuid4())
        self.assertEqual(409, self.scoped_mutation(human, foreign, "otp.email-finish", "POST", "setup-otp-mail", 409)[0])
        mixed = json.loads(json.dumps(finish))
        mixed["target"]["origin"]["humanIssuer"] = "https://foreign.invalid/realms/other"
        self.assertEqual(409, self.scoped_mutation(human, mixed, "otp.email-finish", "POST", "setup-otp-mail", 409)[0])
        self.assertEqual(401, self.scoped_mutation(None, finish, "otp.email-finish", "POST", "setup-otp-mail", 401)[0])
        mail = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials") if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual(1, len(mail))
        self.assertEqual(0, json.loads(mail[0]["credentialData"])["failedVerifications"])
        self.assertFalse(json.loads(mail[0]["credentialData"])["active"])
        self.assertEqual(original, self.admin("GET", "/users/" + self.account_id).get("email"))
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        self.phase("scoped-otp-linked-origin-refusal", absent_owned_reference=True,
                   origin_mismatch=True, missing_human=True, no_attempt=True, no_profile_effect=True)

    def test_linked_email_recreated_same_uuid_credential_cannot_be_adopted_as_sent_incarnation(self):
        human, finish, destination, original, before_mail = self.linked_finish_fixture()
        native = self.admin("GET", "/users/" + self.account_id)
        mail = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials") if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual(1, len(mail))
        data = json.loads(mail[0]["credentialData"])
        old_ttl = data["ttlInSeconds"]
        data["ttlInSeconds"] = old_ttl + 1
        # Native User PUT deliberately ignores updates to an existing credential. Prove a real
        # installer replacement instead: delete the exact owned row, then recreate its UUID with
        # changed immutable data/secret bounds. UUID alone must never adopt this incarnation.
        self.admin("DELETE", "/users/" + self.account_id + "/credentials/" + mail[0]["id"])
        self.assertFalse(any(c["id"] == mail[0]["id"] for c in self.admin("GET", "/users/" + self.account_id + "/credentials")))
        recreated = {"id": mail[0]["id"], "type": "MAIL_OTP_CM", "createdDate": int(time.time() * 1000),
                     "credentialData": canonical(data).decode(),
                     "secretData": canonical({"code": finish["otp"]["initialCode"], "expiry": int(time.time() * 1000) + 600000}).decode()}
        native["credentials"] = [recreated]
        self.admin("PUT", "/users/" + self.account_id, native)
        actual = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials") if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual([mail[0]["id"]], [c["id"] for c in actual])
        self.assertEqual(old_ttl + 1, json.loads(actual[0]["credentialData"])["ttlInSeconds"])
        finish["expectedState"] = self.invoke("read", {"target": finish["target"]}, human, 200)[1]["state"]
        self.assertEqual(409, self.scoped_mutation(human, finish, "otp.email-finish", "POST", "setup-otp-mail", 409)[0])
        current = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials") if c["type"] == "MAIL_OTP_CM"]
        self.assertFalse(json.loads(current[0]["credentialData"])["active"])
        self.assertEqual(0, json.loads(current[0]["credentialData"])["failedVerifications"])
        self.assertEqual(original, self.admin("GET", "/users/" + self.account_id).get("email"))
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        self.phase("scoped-otp-linked-incarnation-refusal", exact_native_drift_proven=True,
                   fresh_cas=True, no_adoption=True, no_attempt=True, no_profile_effect=True)

    def test_expired_sent_email_outcome_uses_fresh_authority_without_resend_or_expiry_extension(self):
        human, finish, destination, original, before_mail = self.linked_finish_fixture(15)
        start = self._last_delivered_start
        original_result = self._last_sent_result
        remaining = start["authorityValidUntil"] + 1 - time.time()
        self.assertLessEqual(remaining, 17)
        time.sleep(max(0, remaining))
        self.assertGreater(int(time.time()), start["authorityValidUntil"])
        fresh_human = self.human()
        self.phase("scoped-otp-expired-sent-outcome-preconditions", actual_committed_sent=True,
                   original_deadline_elapsed=True, fresh_native_human=True,
                   canonical_admin=True, stock_native_denied=True, one_actual_smtp=True)
        status, recovered = self.scoped_mutation(fresh_human, start, "otp.email-start", "PUT", "send-verification-mail", 200)
        self.assertEqual(200, status)
        self.assertEqual(original_result, recovered)
        encoded, signature = recovered["receipt"].split(".")
        self.assertTrue(hmac.compare_digest(hmac.new(CONTEXT_KEY, ("otp-operation-receipt\n" + encoded).encode(), hashlib.sha256).hexdigest(), signature))
        facts = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(start["authorityValidUntil"], facts["authorityValidUntil"])
        self.assertEqual(start["operationId"], facts["operationId"])
        self.assertEqual("SENT", facts["deliveryState"])
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], facts["ownerSubject"])
        missing = json.loads(json.dumps(start)); missing["operationId"] = str(uuid.uuid4())
        self.assertEqual(409, self.scoped_mutation(fresh_human, missing, "otp.email-start", "PUT", "send-verification-mail", 409)[0])
        # A separate absent-intent diagnostic isolates expiry from the unchanged stale CAS.
        missing_current = json.loads(json.dumps(missing))
        missing_current["expectedState"] = self.invoke("read", {"target": start["target"]}, fresh_human, 200)[1]["state"]
        self.assertEqual(403, self.scoped_mutation(fresh_human, missing_current, "otp.email-start", "PUT", "send-verification-mail", 403)[0])
        changed = json.loads(json.dumps(start)); changed["otp"]["email"] = "unowned@fixture.invalid"
        self.assertEqual(409, self.scoped_mutation(fresh_human, changed, "otp.email-start", "PUT", "send-verification-mail", 409)[0])
        self.assertEqual(401, self.scoped_mutation(None, start, "otp.email-start", "PUT", "send-verification-mail", 401)[0])
        self.assertEqual(original, self.admin("GET", "/users/" + self.account_id).get("email"))
        mail = [c for c in self.admin("GET", "/users/" + self.account_id + "/credentials") if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual(1, len(mail)); self.assertFalse(json.loads(mail[0]["credentialData"])["active"])
        self.assertEqual(0, json.loads(mail[0]["credentialData"])["failedVerifications"])
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        self.phase("scoped-otp-expired-sent-outcome-effect", original_mac_deadline=True,
                   exact_saved_outcome=True, original_route_and_body=True,
                   missing_expired_refused_before_prepare=True, changed_refused=True, current_human_required=True,
                   no_smtp=True, no_profile_effect=True, no_credential_effect=True)

    def test_expired_committed_ready_cannot_claim_send_or_extend_original_deadline(self):
        human, target = self.human(), self.target()
        realm = self.admin("GET", "")
        realm["emailTheme"] = "oriso"
        realm["smtpServer"] = {"host": "host.docker.internal", "port": str(self.mail.server_address[1]),
                               "from": "otp-fixture@oriso.org", "auth": "false", "ssl": "false", "starttls": "false"}
        self.admin("PUT", "", realm)
        original = self.admin("GET", "/users/" + self.account_id).get("email")
        before_mail = len(self.mail.messages)
        body = self.email_start_body(human, target, "ready-" + uuid.uuid4().hex + "@oriso.org")
        body["authorityValidUntil"] = int(time.time()) + 15
        frozen = canonical(body)
        self.phase("scoped-otp-ready-fixture-start", original_public_route=True, exact_native_preconditions=True)
        status, ready = self.scoped_mutation(human, body, "otp.email-start", "PUT", "send-verification-mail", 202,
                                             fixture_operation=body["operationId"])
        self.assertEqual(202, status)
        self.assertEqual({"State": "READY", "Tx": "true", "Revoked": "true", "Expired": "false"}, self._ready_observation)
        self.assertEqual("READY", ready["deliveryState"])
        self.assertEqual(before_mail, len(self.mail.messages), "Failed original fresh-auth callback must not send")
        self.assertEqual(401, self.scoped_mutation(human, body, "otp.email-start", "PUT", "send-verification-mail", 401)[0])
        credentials = self.admin("GET", "/users/" + self.account_id + "/credentials")
        mail = [c for c in credentials if c["type"] == "MAIL_OTP_CM"]
        self.assertEqual(1, len(mail)); self.assertFalse(json.loads(mail[0]["credentialData"])["active"])
        remaining = body["authorityValidUntil"] + 1 - time.time()
        self.assertLessEqual(remaining, 17)
        time.sleep(max(0, remaining))
        fresh = self.human()
        self.phase("scoped-otp-expired-ready-preconditions", actual_committed_ready=True,
                   original_fresh_auth_callback_refused=True, original_deadline_elapsed=True,
                   current_native_human=True, no_smtp=True)
        status, _ = self.scoped_mutation(fresh, body, "otp.email-start", "PUT", "send-verification-mail", 503,
                                        fixture_operation=body["operationId"])
        self.assertEqual(503, status)
        self.assertEqual({"State": "READY", "Tx": "true", "Revoked": None, "Expired": "true"}, self._ready_observation)
        self.assertEqual(frozen, canonical(body))
        self.assertEqual(credentials, self.admin("GET", "/users/" + self.account_id + "/credentials"))
        self.assertEqual(original, self.admin("GET", "/users/" + self.account_id).get("email"))
        self.assertEqual(before_mail, len(self.mail.messages))
        self.phase("scoped-otp-expired-ready-refusal", original_body_id_cas_deadline=True,
                   no_prepare_or_claim_or_send=True, no_native_effect=True, actual_committed_ready=True)

    def email_start_body(self, human, target, email):
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        return {"target": target, "operationId": str(uuid.uuid4()),
                "expectedState": current["state"], "authorityValidUntil": int(time.time()) + 120,
                "otp": {"initialCode": None, "secret": None, "email": email}}

    def test_current_self_email_start_refuses_another_native_accounts_email_before_effects(self):
        human, target = self.human(), self.target()
        realm = self.admin("GET", "")
        realm["emailTheme"] = "oriso"
        realm["smtpServer"] = {
            "host": "host.docker.internal", "port": str(self.mail.server_address[1]),
            "from": "otp-fixture@oriso.org", "auth": "false", "ssl": "false", "starttls": "false",
        }
        self.admin("PUT", "", realm)
        username = "email-owner-" + uuid.uuid4().hex
        email = username + "@oriso.org"
        self.admin("POST", "/users", {"username": username, "email": email, "enabled": True})
        owners = self.admin("GET", "/users?username=" + username + "&exact=true")
        self.assertEqual(1, len(owners))
        self.assertEqual(email, owners[0]["email"])
        self.addCleanup(self.admin, "DELETE", "/users/" + owners[0]["id"])
        body = self.email_start_body(human, target, email)
        credentials = self.admin("GET", "/users/" + self.account_id + "/credentials")
        self.assertFalse(any(x["type"] in {"otp", "MAIL_OTP_CM"} for x in credentials))
        before_mail = len(self.mail.messages)
        self.phase("scoped-otp-email-foreign-destination-preconditions", actual_current_self=True,
                   real_other_native_owner=True, exact_bounded_cas=True, no_prior_owned_mail=True)
        status, _ = self.scoped_mutation(human, body, "otp.email-start", "PUT", "send-verification-mail", 412)
        self.assertEqual(412, status)
        self.assertEqual(credentials, self.admin("GET", "/users/" + self.account_id + "/credentials"))
        self.assertEqual(before_mail, len(self.mail.messages))

    def test_current_self_email_smtp_unknown_is_durable_and_exact_retry_never_resends(self):
        human, target = self.human(), self.target()
        realm = self.admin("GET", "")
        realm["emailTheme"] = "oriso"
        realm["smtpServer"] = {
            "host": "host.docker.internal", "port": str(self.mail.server_address[1]),
            "from": "otp-fixture@oriso.org", "auth": "false", "ssl": "false", "starttls": "false",
        }
        self.admin("PUT", "", realm)
        self.mail.reject_after_data = True
        self.addCleanup(setattr, self.mail, "reject_after_data", False)
        body = self.email_start_body(human, target, "unknown-" + uuid.uuid4().hex + "@oriso.org")
        before_mail = len(self.mail.messages)
        self.phase("scoped-otp-email-unknown-preconditions", actual_current_self=True,
                   real_smtp_accepts_bytes_then451=True, exact_bounded_cas=True)
        self.assertEqual(202, self.scoped_mutation(human, body, "otp.email-start", "PUT",
                                                  "send-verification-mail", 202)[0])
        self.assertEqual(before_mail + 1, len(self.mail.messages))
        native = self.admin("GET", "/users/" + self.account_id + "/credentials")
        pending = [x for x in native if x["type"] == "MAIL_OTP_CM"]
        self.assertEqual(1, len(pending))
        for _ in range(2):
            self.assertEqual(503, self.scoped_mutation(human, body, "otp.email-start", "PUT",
                                                      "send-verification-mail", 503)[0])
            self.assertEqual(before_mail + 1, len(self.mail.messages))
            self.assertEqual(pending, [x for x in self.admin("GET", "/users/" + self.account_id
                                                            + "/credentials") if x["type"] == "MAIL_OTP_CM"])
        self.phase("scoped-otp-email-unknown-fenced", unknown_visible=True, one_smtp_attempt=True,
                   no_retry_send=True, no_credential_replacement=True)

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
