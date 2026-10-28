#!/usr/bin/env python3
"""Isolated HTTP proof of the UNACTIVATED SMTP-only proposal (Keycloak#57).

SMTP_CONTROL_TEST_JAR points to the locally built standalone jar. Unset it to
measure the native-only RED. No shared runtime, image packaging or real secrets.
"""
import base64
import concurrent.futures
import hmac
import json
import os
import re
import subprocess
import sys
import time
import unittest
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

IMAGE = "quay.io/keycloak/keycloak@sha256:9b0330756022422149aa6502eb2def8cd47c6e1b000c7c65cdb13e7c0133e992"
KEY = b"synthetic-smtp-control-key-00001"  # Exactly 32 bytes; the accepted lower bound.
ROLES = ["config-wizard", "invitation-reservations", "consultant-import", "smtp-sync"]
AUDIENCES = ["oriso-task-commands", "tenantservice", "agencyservice", "consultingtypeservice", "userservice"]
SUBJECT = "15438b20-6ab7-473f-93c5-8aac79a9ff81"
REALM = "smtp-control-fixture"
SECRET = "synthetic-mail-client-secret-00000000000001"
INSTALLER = "synthetic-installer-password-0001"
PASSWORD = "synthetic-SMTP-password-0001"
PAYLOAD = {"revision": 1, "globalSmtpEnabled": True,
           "globalFeatureSystemNotificationEmailsEnabled": True,
           "globalSmtpHost": "smtp.fixture.internal", "globalSmtpPort": 587,
           "globalSmtpFrom": "Fixture <mail@fixture.internal>",
           "globalSmtpUsername": "synthetic-smtp-user", "globalSmtpPassword": PASSWORD,
           "globalSmtpSecure": False}


def canonical(body):
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def encoded(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def proof(body, operation="SMTP_APPLY", **changes):
    now = int(time.time())
    claims = {"iss": "oriso-smtp-sync", "aud": "oriso-smtp-control",
              "purpose": "SMTP_SYNC", "operation": operation, "actor": "SETUP",
              "realm": REALM, "target": REALM, "taskClient": "backend-setup",
              "taskSubject": SUBJECT,
              "payloadDigest": hmac.digest(KEY, b"payload\n" + canonical(body), "sha256").hex(),
              "method": "GET" if operation == "SMTP_STATUS" else "PUT",
              "jti": str(uuid.uuid4()), "nonce": uuid.uuid4().hex,
              "iat": now, "exp": now + 60}
    claims.update(changes)
    payload = encoded(canonical(claims))
    return payload + "." + encoded(hmac.digest(KEY, b"proof\n" + payload.encode(), "sha256"))


def call(base, method, path, body=None, token=None, context=None, form=False):
    headers = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if context:
        headers["X-ORISO-Task-Context"] = context
    data = None if body is None else (urlencode(body).encode() if form else json.dumps(body).encode())
    try:
        with urlopen(Request(base + path, data=data, headers=headers, method=method), timeout=30) as response:
            status, raw = response.status, response.read()
    except HTTPError as error:
        status, raw = error.code, error.read()
        error.close()
    return status, json.loads(raw) if raw else None


class SmtpControlPermissions(unittest.TestCase):
    @classmethod
    def require_headroom(cls):
        if sys.platform == "darwin":
            output = subprocess.check_output(["memory_pressure", "-Q"], text=True)
            match = re.search(r"memory free percentage:\s*(\d+)%", output)
            if match is None or int(match[1]) < 25:
                raise AssertionError("Native SMTP fixture requires25 percent memory headroom")

    @classmethod
    def setUpClass(cls):
        cls.require_headroom()
        cls.run_id = uuid.uuid4().hex
        cls.name = "oriso-smtp-proposal-" + cls.run_id[:12]
        cls.network = "oriso-smtp-native-" + cls.run_id[:12]
        cls.addClassCleanup(cls.stop)
        subprocess.run(["docker", "network", "create", "--label", "oriso-smtp-run-id=" + cls.run_id,
                        cls.network], check=True, capture_output=True)
        cmd = ["docker", "run", "-d", "--name", cls.name, "--label", "oriso-smtp-control-test=true",
               "--label", "oriso-smtp-run-id=" + cls.run_id, "--network", cls.network,
               "--memory=768m", "--memory-swap=768m", "--cpus=2", "--pids-limit=256",
               "-p", "127.0.0.1::8080", "-e", "JAVA_OPTS_APPEND=-Xmx384m -XX:ActiveProcessorCount=2",
               "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-installer",
               "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + INSTALLER,
               "-e", "ORISO_SMTP_CONTROL_ENABLED=true", "-e", "ORISO_SMTP_CONTROL_REALM=" + REALM,
               "-e", "IDENTITY_SETUP_SERVICE_SUBJECT=" + SUBJECT,
               "-e", "ORISO_TASK_CONTEXT_KEY=" + base64.b64encode(KEY).decode()]
        jar = os.environ.get("SMTP_CONTROL_TEST_JAR")
        if jar:
            if not Path(jar).is_file():
                raise AssertionError("SMTP_CONTROL_TEST_JAR must name an existing local jar")
            cmd += ["-v", str(Path(jar).resolve()) + ":/opt/keycloak/providers/smtp-control-spi.jar:ro"]
        cmd += [IMAGE, "start-dev"]
        subprocess.run(cmd, check=True, capture_output=True)
        address = subprocess.run(["docker", "port", cls.name, "8080/tcp"], check=True,
                                 capture_output=True, text=True).stdout.strip().splitlines()[0]
        cls.base = "http://" + address
        deadline = time.monotonic() + 180
        while True:
            try:
                status, response = call(cls.base, "POST", "/realms/master/protocol/openid-connect/token",
                                        {"client_id": "admin-cli", "grant_type": "password",
                                         "username": "synthetic-installer", "password": INSTALLER}, form=True)
                if status == 200:
                    cls.installer = response["access_token"]
                    break
            except (URLError, OSError, TimeoutError):
                pass
            if time.monotonic() > deadline:
                raise AssertionError("isolated Keycloak readiness failed; inspect local container")
            time.sleep(1)

    @classmethod
    def stop(cls):
        inspected = subprocess.run(["docker", "inspect", "--format",
            '{{index .Config.Labels "oriso-smtp-run-id"}}', cls.name], capture_output=True, text=True)
        logs = None
        if inspected.returncode == 0:
            if inspected.stdout.strip() != cls.run_id:
                raise AssertionError("Refuse SMTP fixture cleanup: run label differs")
            logs = subprocess.run(["docker", "logs", cls.name], capture_output=True, text=True)
            subprocess.run(["docker", "rm", "-f", cls.name], check=True, capture_output=True)
        network = subprocess.run(["docker", "network", "inspect", "--format",
            '{{index .Labels "oriso-smtp-run-id"}}', cls.network], capture_output=True, text=True)
        if network.returncode == 0:
            if network.stdout.strip() != cls.run_id:
                raise AssertionError("Refuse SMTP fixture network cleanup: run label differs")
            subprocess.run(["docker", "network", "rm", cls.network], check=True, capture_output=True)
        if logs is None:
            return
        destination = os.environ.get("SMTP_CONTROL_TEST_SERVER_LOG")
        if destination:
            sanitized = logs.stdout + logs.stderr
            for value in (PASSWORD, SECRET, INSTALLER, base64.b64encode(KEY).decode()):
                sanitized = sanitized.replace(value, "[synthetic credential redacted]")
            Path(destination).write_text(sanitized)
        # Test body credentials must never appear in provider/server log output.
        if PASSWORD in logs.stdout + logs.stderr:
            raise AssertionError("SMTP credential appeared in isolated server logs")

    def admin(self, method, path="", body=None):
        status, response = call(self.base, method, "/admin/realms/" + REALM + path, body, self.installer)
        self.assertLess(status, 300, (method, path, status))
        return response

    def setUp(self):
        self.require_headroom()
        client = {"clientId": "backend-setup", "secret": SECRET,
                   "publicClient": False, "serviceAccountsEnabled": True,
                   "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
                   "fullScopeAllowed": False, "defaultClientScopes": [], "optionalClientScopes": [],
                   "protocolMappers": [
                       {"name": "realm-roles", "protocol": "openid-connect",
                        "protocolMapper": "oidc-usermodel-realm-role-mapper",
                        "config": {"claim.name": "realm_access.roles", "access.token.claim": "true",
                                   "multivalued": "true", "jsonType.label": "String"}},
                       *[{"name": "audience" if audience == "oriso-task-commands" else "audience-" + audience,
                          "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                          "config": {"included.custom.audience": audience, "access.token.claim": "true"}}
                         for audience in AUDIENCES]]}
        status, response = call(self.base, "POST", "/admin/realms", {"realm": REALM, "id": REALM,
                        "enabled": True, "adminPermissionsEnabled": True,
                        "displayName": "unchanged", "registrationAllowed": False,
                        "smtpServer": {"host": "before.fixture.internal", "port": "25",
                                       "from": "before@fixture.internal"}, "clients": [client],
                        "roles": {"realm": [{"name": role} for role in ROLES]},
                        "users": [{"id": SUBJECT, "username": "service-account-backend-setup",
                                   "enabled": True, "serviceAccountClientId": "backend-setup"}]}, self.installer)
        self.assertEqual(201, status, response)
        self.addCleanup(call, self.base, "DELETE", "/admin/realms/" + REALM, token=self.installer)
        self.client = self.admin("GET", "/clients?" + urlencode({"clientId": "backend-setup"}))[0]["id"]
        mapped = self.admin("GET", "/users/" + SUBJECT + "/role-mappings/realm")
        if mapped:
            self.admin("DELETE", "/users/" + SUBJECT + "/role-mappings/realm", mapped)
        roles = [self.admin("GET", "/roles/" + role) for role in ROLES]
        self.admin("POST", "/users/" + SUBJECT + "/role-mappings/realm", roles)
        self.admin("POST", "/clients/" + self.client + "/scope-mappings/realm", roles)
        self.protected_parent, self.technical_group = self.prepare_protected_setup_membership()

    def token(self):
        status, response = call(self.base, "POST", "/realms/" + REALM + "/protocol/openid-connect/token",
                                {"grant_type": "client_credentials", "client_id": "backend-setup",
                                 "client_secret": SECRET}, form=True)
        self.assertEqual(200, status)
        return response["access_token"]

    def prepare_protected_setup_membership(self):
        self.admin("POST", "/groups", {"name": "protected-admins"})
        parent = self.admin("GET", "/group-by-path/protected-admins")["id"]
        self.admin("POST", "/groups/" + parent + "/children", {"name": "technical-identities"})
        group = self.admin("GET", "/group-by-path/protected-admins/technical-identities")["id"]
        self.admin("PUT", "/users/" + SUBJECT + "/groups/" + group)
        return parent, group

    def test_real_canonical_protected_setup_can_apply_and_read_status(self):
        parent, group = self.protected_parent, self.technical_group
        self.assertEqual([group], [g["id"] for g in self.admin("GET", "/users/" + SUBJECT + "/groups")])
        for gid in (parent, group):
            self.assertEqual({}, self.admin("GET", "/groups/" + gid + "/role-mappings"))
        status, result = self.smtp(PAYLOAD, proof(PAYLOAD))
        self.assertEqual(200, status, result)
        self.assertEqual({"revision": 1, "status": "APPLIED"}, result)
        self.assertEqual("smtp.fixture.internal", self.admin("GET")["smtpServer"]["host"])
        status, result = self.smtp(context=proof({}, "SMTP_STATUS"), method="GET")
        self.assertEqual(200, status, result)
        self.assertEqual({"revision": 1, "status": "APPLIED"}, result)

    def test_missing_or_extra_native_bearer_audience_is_denied_before_any_write(self):
        original = self.admin("GET", "/clients/" + self.client)
        before = self.admin("GET")["smtpServer"]
        for audiences in (["oriso-task-commands"], AUDIENCES + ["oriso-smtp-control"]):
            with self.subTest(audiences=audiences):
                changed = dict(original)
                changed["protocolMappers"] = [m for m in original["protocolMappers"]
                                                if m["protocolMapper"] != "oidc-audience-mapper"]
                changed["protocolMappers"] += [
                    {"name": "native-audience-" + str(index), "protocol": "openid-connect",
                     "protocolMapper": "oidc-audience-mapper",
                     "config": {"included.custom.audience": audience, "access.token.claim": "true"}}
                    for index, audience in enumerate(audiences)]
                self.admin("PUT", "/clients/" + self.client, changed)
                bearer = self.token()
                payload = bearer.split(".")[1]
                issued = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
                self.assertEqual(set(audiences), set(issued["aud"])
                                 if isinstance(issued["aud"], list) else {issued["aud"]})
                self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD), token=bearer)[0])
                self.assertEqual(before, self.admin("GET")["smtpServer"])
        self.admin("PUT", "/clients/" + self.client, original)
        self.assert_unconsumed_revision(self.token())

    def assert_membership_refusal_preserves_revision(self, token):
        before = self.admin("GET")["smtpServer"]
        self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD), token=token)[0])
        self.assertEqual(403, self.smtp(context=proof({}, "SMTP_STATUS"), method="GET", token=token)[0])
        self.assertEqual(before, self.admin("GET")["smtpServer"])

    def assert_unconsumed_revision(self, token):
        status, result = self.smtp(context=proof({}, "SMTP_STATUS"), method="GET", token=token)
        self.assertEqual(200, status, result)
        self.assertEqual({"revision": -1, "status": "NOT_APPLIED"}, result)

    def test_missing_arbitrary_or_extra_membership_is_denied(self):
        token = self.token()
        membership = "/users/" + SUBJECT + "/groups/"
        self.admin("DELETE", membership + self.technical_group)
        self.assert_membership_refusal_preserves_revision(token)
        self.admin("POST", "/groups", {"name": "arbitrary-mail-group"})
        arbitrary = self.admin("GET", "/group-by-path/arbitrary-mail-group")["id"]
        self.admin("PUT", membership + arbitrary)
        self.assert_membership_refusal_preserves_revision(token)
        self.admin("PUT", membership + self.technical_group)
        self.assert_membership_refusal_preserves_revision(token)
        self.admin("DELETE", membership + arbitrary)
        self.assert_unconsumed_revision(token)

    def test_group_and_ancestor_ambient_roles_are_denied_even_for_existing_setup_role(self):
        token = self.token()
        role = self.admin("GET", "/roles/smtp-sync")
        for group in (self.technical_group, self.protected_parent):
            with self.subTest(group=group):
                path = "/groups/" + group + "/role-mappings/realm"
                self.admin("POST", path, [role])
                self.assert_membership_refusal_preserves_revision(token)
                self.admin("DELETE", path, [role])
                self.assert_unconsumed_revision(token)

    def test_lookalike_membership_under_an_extra_ancestor_is_denied(self):
        token = self.token()
        self.admin("POST", "/groups", {"name": "unexpected-root"})
        root = self.admin("GET", "/group-by-path/unexpected-root")["id"]
        self.admin("POST", "/groups/" + root + "/children", {"name": "protected-admins"})
        parent = self.admin("GET", "/group-by-path/unexpected-root/protected-admins")["id"]
        self.admin("POST", "/groups/" + parent + "/children", {"name": "technical-identities"})
        group = self.admin("GET", "/group-by-path/unexpected-root/protected-admins/technical-identities")["id"]
        membership = "/users/" + SUBJECT + "/groups/"
        self.admin("DELETE", membership + self.technical_group)
        self.admin("PUT", membership + group)
        self.assert_membership_refusal_preserves_revision(token)
        self.admin("DELETE", membership + group)
        self.admin("PUT", membership + self.technical_group)
        self.assert_unconsumed_revision(token)

    def smtp(self, body=None, context=None, method="PUT", token=None, realm=REALM):
        return call(self.base, method, "/realms/" + realm + "/oriso-smtp-control/v1/smtp", body,
                    self.token() if token is None else token, context)

    def test_smtp_only_change_and_public_status_readback(self):
        status, result = self.smtp(PAYLOAD, proof(PAYLOAD))
        self.assertEqual(200, status, result)
        self.assertEqual({"revision": 1, "status": "APPLIED"}, result)
        actual = self.admin("GET")
        self.assertEqual("smtp.fixture.internal", actual["smtpServer"]["host"])
        self.assertEqual("**********", actual["smtpServer"]["password"])
        self.assertEqual("unchanged", actual["displayName"])
        self.assertFalse(actual["registrationAllowed"])
        status, result = self.smtp(context=proof({}, "SMTP_STATUS"), method="GET")
        self.assertEqual(200, status)
        self.assertEqual({"revision": 1, "status": "APPLIED"}, result)
        self.assertNotIn(PASSWORD, json.dumps(result))

    def test_invalid_disabled_snapshot_cannot_clear_smtp_or_consume_revision(self):
        before = self.admin("GET")["smtpServer"]
        body = dict(PAYLOAD, globalSmtpEnabled=False,
                    globalSmtpFrom="first@fixture.internal, second@fixture.internal")
        status, _ = self.smtp(body, proof(body))
        self.assertEqual(400, status)
        self.assertEqual(before, self.admin("GET")["smtpServer"])
        status, result = self.smtp(context=proof({}, "SMTP_STATUS"), method="GET")
        self.assertEqual(200, status)
        self.assertEqual({"revision": -1, "status": "NOT_APPLIED"}, result)

    def test_setup_bearer_without_control_proof_is_denied(self):
        before = self.admin("GET")
        for method, body in (("PUT", PAYLOAD), ("GET", None)):
            with self.subTest(method=method):
                status, _ = self.smtp(body, method=method)
                self.assertEqual(403, status)
        status, _ = self.smtp(PAYLOAD, proof(PAYLOAD), token="")
        self.assertEqual(401, status)
        self.assertEqual(before, self.admin("GET"))

    def test_mail_with_valid_common_key_proof_cannot_configure_smtp(self):
        # A real canonical MAIL bearer and knowledge of the shared key confer no SETUP authority.
        before = self.admin("GET")
        roles = ["system-email-delivery", "notification-dispatch", "notifications-technical"]
        for role in roles:
            self.admin("POST", "/roles", {"name": role})
        client = self.admin("GET", "/clients/" + self.client)
        client.pop("id")
        client["clientId"] = "backend-mail"
        client["secret"] = "synthetic-delivery-secret"
        client["protocolMappers"] = [m for m in client["protocolMappers"]
            if m.get("config", {}).get("included.custom.audience") != "oriso-task-commands"]
        for mapper in client["protocolMappers"]:
            mapper.pop("id", None)
        self.admin("POST", "/clients", client)
        mail_client = self.admin("GET", "/clients?clientId=backend-mail")[0]["id"]
        subject = self.admin("GET", "/clients/" + mail_client + "/service-account-user")["id"]
        defaults = self.admin("GET", "/users/" + subject + "/role-mappings/realm")
        if defaults:
            self.admin("DELETE", "/users/" + subject + "/role-mappings/realm", defaults)
        grants = [self.admin("GET", "/roles/" + role) for role in roles]
        self.admin("POST", "/users/" + subject + "/role-mappings/realm", grants)
        self.admin("POST", "/clients/" + mail_client + "/scope-mappings/realm", grants)
        self.admin("PUT", "/users/" + subject + "/groups/" + self.technical_group)
        status, response = call(self.base, "POST", "/realms/" + REALM + "/protocol/openid-connect/token",
            {"grant_type": "client_credentials", "client_id": "backend-mail",
             "client_secret": "synthetic-delivery-secret"}, form=True)
        self.assertEqual(200, status)
        token = response["access_token"]
        for claims in ({"actor": "MAIL", "taskClient": "backend-mail", "taskSubject": subject}, {}):
            self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD, **claims), token=token)[0])
        self.assertEqual(before, self.admin("GET"))

    def test_signed_context_is_bound_to_purpose_identity_realm_method_payload_and_ttl(self):
        before = self.admin("GET")
        token = self.token()
        now = int(time.time())
        changes = [{"purpose": "SYSTEM_EMAIL_DELIVERY"}, {"actor": "MAIL"},
                   {"operation": "SMTP_STATUS"}, {"method": "GET"},
                   {"realm": "foreign"}, {"target": "foreign"},
                   {"taskClient": "backend-runtime"}, {"taskSubject": str(uuid.uuid4())},
                   {"iss": "untrusted"}, {"aud": "userservice"}, {"payloadDigest": "0" * 64},
                   {"iat": now - 65, "exp": now - 5}, {"iat": now + 120, "exp": now + 180},
                   {"exp": now + 3600}, {"jti": "not-a-uuid"}, {"nonce": "not-a-nonce"},
                   {"extra": "unaccepted"}]
        for change in changes:
            with self.subTest(claim=next(iter(change))):
                status, _ = self.smtp(PAYLOAD, proof(PAYLOAD, **change), token=token)
                self.assertEqual(403, status)
        signed = proof(PAYLOAD)
        malformed = (signed + ".extra", signed.split(".")[0] + "." + encoded(b"0" * 32), "not-a-proof")
        for context in malformed:
            status, _ = self.smtp(PAYLOAD, context, token=token)
            self.assertEqual(403, status)
        # A valid MAC authenticates the complete bytes, not just the first JSON value.
        claims = base64.urlsafe_b64decode(signed.split(".")[0] + "=" * (-len(signed.split(".")[0]) % 4))
        for trailing in (b" {}", b" true", b"\n[]"):
            with self.subTest(trailing_json=trailing.decode().strip()):
                payload = encoded(claims + trailing)
                context = payload + "." + encoded(hmac.digest(KEY, b"proof\n" + payload.encode(), "sha256"))
                self.assertEqual(403, self.smtp(PAYLOAD, context, token=token)[0])
                self.assertEqual(before, self.admin("GET"))
        status, _ = self.smtp(dict(PAYLOAD, globalSmtpHost="changed.fixture.internal"), signed, token=token)
        self.assertEqual(403, status)
        status, _ = self.smtp(context=proof({}, method="PUT"), method="GET", token=token)
        self.assertEqual(403, status)
        self.assertEqual(before, self.admin("GET"))

    def test_mixed_unrelated_and_invalid_fields_never_mutate_receiver_state(self):
        before = self.admin("GET")
        changes = [{"registrationAllowed": True}, {"displayName": "unrelated"},
                   {"smtpServer": {"host": "unaccepted.fixture.internal"}},
                   {"globalSmtpHost": "h" * 256}, {"globalSmtpHost": "bad\r\nhost"},
                   {"globalSmtpUsername": "u" * 4097}, {"globalSmtpPassword": "p" * 4097},
                   {"globalSmtpPort": 0}, {"globalSmtpPort": 65536}, {"globalSmtpPort": "25x"},
                   {"globalSmtpFrom": "one@fixture.internal, two@fixture.internal"},
                   {"globalSmtpEnabled": "true"}, {"globalSmtpSecure": 1},
                   {"revision": -1}, {"revision": 1.5}, {"revision": 2 ** 63}]
        token = self.token()
        for change in changes:
            with self.subTest(field=next(iter(change))):
                body = dict(PAYLOAD, **change)
                status, _ = self.smtp(body, proof(body), token=token)
                self.assertEqual(400, status)
                self.assertEqual(before, self.admin("GET"))
        status, result = self.smtp(context=proof({}, "SMTP_STATUS"), method="GET", token=token)
        self.assertEqual(200, status)
        self.assertEqual({"revision": -1, "status": "NOT_APPLIED"}, result)

    def test_setup_identity_cannot_use_native_realm_user_role_or_policy_administration(self):
        before = self.admin("GET")
        self.admin("POST", "/users", {"username": "existing-human", "enabled": True})
        human = self.admin("GET", "/users?username=existing-human&exact=true")[0]["id"]
        management = self.admin("GET", "/clients?clientId=realm-management")[0]["id"]
        admin_permissions = self.admin("GET", "/clients?clientId=admin-permissions")[0]["id"]
        realm_role = self.admin("GET", "/roles/smtp-sync")
        management_role = self.admin("GET", "/clients/" + management + "/roles/manage-realm")
        rows = [("GET", "", None), ("PUT", "", {"registrationAllowed": True}),
                ("PUT", "", {"smtpServer": {"host": "native-denied.fixture.internal"}}),
                ("GET", "/users", None), ("POST", "/users", {"username": "denied-human"}),
                ("PUT", "/users/" + human, {"firstName": "denied"}),
                ("DELETE", "/users/" + human, None),
                ("PUT", "/users/" + human + "/reset-password",
                 {"type": "password", "value": "synthetic-denied-password", "temporary": True}),
                ("POST", "/users/" + human + "/role-mappings/realm", [realm_role]),
                ("POST", "/users/" + SUBJECT + "/role-mappings/clients/" + management, [management_role]),
                ("POST", "/roles", {"name": "denied-role"}),
                ("POST", "/clients/" + admin_permissions + "/authz/resource-server/policy/user",
                 {"name": "denied-policy", "users": [SUBJECT]})]
        token = self.token()
        for method, path, body in rows:
            with self.subTest(method=method, path=path):
                status, _ = call(self.base, method, "/admin/realms/" + REALM + path, body, token,
                                 proof(PAYLOAD))
                self.assertEqual(403, status)
        self.assertEqual(before, self.admin("GET"))
        self.assertEqual([], self.admin("GET", "/users?username=denied-human&exact=true"))
        self.assertNotIn("firstName", self.admin("GET", "/users/" + human))

    def test_current_inherited_grants_groups_composites_and_native_roles_are_denied(self):
        token = self.token()  # Model-state changes below must also invalidate an older token.
        before = self.admin("GET")["smtpServer"]
        defaults = self.admin("GET", "/roles/default-roles-" + REALM)
        self.admin("POST", "/users/" + SUBJECT + "/role-mappings/realm", [defaults])
        self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD), token=token)[0])
        self.admin("DELETE", "/users/" + SUBJECT + "/role-mappings/realm", [defaults])
        self.admin("POST", "/groups", {"name": "unexpected-mail-group"})
        group = self.admin("GET", "/groups?search=unexpected-mail-group")[0]["id"]
        self.admin("PUT", "/users/" + SUBJECT + "/groups/" + group)
        self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD), token=token)[0])
        self.admin("DELETE", "/users/" + SUBJECT + "/groups/" + group)
        management = self.admin("GET", "/clients?clientId=realm-management")[0]["id"]
        role = self.admin("GET", "/clients/" + management + "/roles/manage-realm")
        self.admin("POST", "/users/" + SUBJECT + "/role-mappings/clients/" + management, [role])
        self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD), token=token)[0])
        self.admin("DELETE", "/users/" + SUBJECT + "/role-mappings/clients/" + management, [role])
        self.admin("POST", "/roles/smtp-sync/composites", [role])
        self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD), token=token)[0])
        self.assertEqual(before, self.admin("GET")["smtpServer"])

    def test_foreign_realm_and_wrong_client_or_audience_are_denied(self):
        foreign = REALM + "-foreign"
        status, _ = call(self.base, "POST", "/admin/realms", {"realm": foreign, "enabled": True,
                        "registrationAllowed": False}, self.installer)
        self.assertEqual(201, status)
        self.addCleanup(call, self.base, "DELETE", "/admin/realms/" + foreign, token=self.installer)
        self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD), realm=foreign)[0])
        self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD), realm="master")[0])
        mapper = self.admin("GET", "/clients/" + self.client + "/protocol-mappers/models")
        audience = next(value for value in mapper if value["name"] == "audience")
        audience["config"]["included.custom.audience"] = "realm-management"
        self.admin("PUT", "/clients/" + self.client + "/protocol-mappers/models/" + audience["id"], audience)
        self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD))[0])
        other = self.admin("GET", "/clients/" + self.client)
        other.pop("id")
        other["clientId"], other["secret"] = "backend-runtime", SECRET
        other["protocolMappers"] = [{"name": "aud", "protocol": "openid-connect",
                                    "protocolMapper": "oidc-audience-mapper", "config": {
                                        "included.custom.audience": "oriso-task-commands",
                                        "access.token.claim": "true"}}]
        self.admin("POST", "/clients", other)
        status, result = call(self.base, "POST", "/realms/" + REALM + "/protocol/openid-connect/token",
                              {"grant_type": "client_credentials", "client_id": "backend-runtime",
                               "client_secret": SECRET}, form=True)
        self.assertEqual(200, status)
        self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD), token=result["access_token"])[0])
        status, actual = call(self.base, "GET", "/admin/realms/" + foreign, token=self.installer)
        self.assertEqual(200, status)
        self.assertFalse(actual["registrationAllowed"])

    def test_native_fgap_privilege_without_a_token_role_is_denied_at_smtp_receiver(self):
        self.admin("POST", "/users", {"username": "fgap-human", "enabled": True})
        human = self.admin("GET", "/users?username=fgap-human&exact=true")[0]["id"]
        client = self.admin("GET", "/clients?clientId=admin-permissions")[0]["id"]
        path = "/clients/" + client + "/authz/resource-server"
        self.admin("POST", path + "/policy/user", {"name": "unexpected-mail-management",
                   "logic": "POSITIVE", "users": [SUBJECT]})
        self.admin("POST", path + "/permission/scope", {"name": "unexpected-mail-user-power",
                   "resourceType": "Users", "scopes": ["manage"], "policies": ["unexpected-mail-management"]})
        token = self.token()
        status, _ = call(self.base, "PUT", "/admin/realms/" + REALM + "/users/" + human,
                         {"firstName": "fixture-policy-control"}, token)
        self.assertEqual(204, status)  # Installer-injected native grant is real, not mocked.
        before = self.admin("GET")["smtpServer"]
        self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD), token=token)[0])
        self.assertEqual(before, self.admin("GET")["smtpServer"])

    def test_target_scoped_native_user_power_invalidates_smtp_authorization(self):
        self.admin("POST", "/users", {"username": "scoped-fgap-human", "enabled": True})
        human = self.admin("GET", "/users?username=scoped-fgap-human&exact=true")[0]["id"]
        self.install_scoped_native_permission("Users", human, ["manage"])
        token = self.token()
        status, _ = call(self.base, "PUT", "/admin/realms/" + REALM + "/users/" + human,
                         {"firstName": "target-scoped-policy-control"}, token)
        self.assertEqual(204, status)  # Target permission really works without a management role.
        self.assertEqual("target-scoped-policy-control", self.admin("GET", "/users/" + human)["firstName"])
        self.assert_native_grant_excludes_smtp(token)

    def test_target_scoped_native_client_power_invalidates_smtp_authorization(self):
        self.admin("POST", "/clients", {"clientId": "scoped-client-target", "enabled": True})
        target = self.admin("GET", "/clients?clientId=scoped-client-target")[0]["id"]
        self.install_scoped_native_permission("Clients", target, ["manage"])
        token = self.token()
        status, _ = call(self.base, "PUT", "/admin/realms/" + REALM + "/clients/" + target,
                         {"name": "target-scoped-policy-control"}, token)
        self.assertEqual(204, status)
        self.assertEqual("target-scoped-policy-control", self.admin("GET", "/clients/" + target)["name"])
        self.assert_native_grant_excludes_smtp(token)

    def install_scoped_native_permission(self, resource_type, target, scopes):
        client = self.admin("GET", "/clients?clientId=admin-permissions")[0]["id"]
        path = "/clients/" + client + "/authz/resource-server"
        condition = "unexpected-scoped-mail-power-" + resource_type
        self.admin("POST", path + "/policy/user", {"name": condition,
                   "logic": "POSITIVE", "users": [SUBJECT]})
        created = self.admin("POST", path + "/permission/scope", {"name": "unexpected-scoped-mail-permission-" + resource_type,
                   "resourceType": resource_type, "resources": [target],
                   "scopes": scopes, "policies": [condition]})
        permission = path + "/policy/" + created["id"]
        self.native_permission_paths = getattr(self, "native_permission_paths", []) + [permission]
        return permission

    def test_target_scoped_native_group_power_invalidates_smtp_authorization(self):
        self.admin("POST", "/groups", {"name": "scoped-group-target"})
        group = self.admin("GET", "/groups?search=scoped-group-target")[0]["id"]
        self.install_scoped_native_permission("Groups", group, ["view"])
        token = self.token()
        status, result = call(self.base, "GET", "/admin/realms/" + REALM + "/groups/" + group, token=token)
        self.assertEqual(200, status)
        self.assertEqual("scoped-group-target", result["name"])
        self.assert_native_grant_excludes_smtp(token)

    def test_target_scoped_native_role_power_invalidates_smtp_authorization(self):
        self.admin("POST", "/users", {"username": "role-scope-human", "enabled": True})
        human = self.admin("GET", "/users?username=role-scope-human&exact=true")[0]["id"]
        self.admin("POST", "/roles", {"name": "scoped-role-target"})
        role = self.admin("GET", "/roles/scoped-role-target")
        user_permission = self.install_scoped_native_permission("Users", human, ["map-roles"])
        self.install_scoped_native_permission("Roles", role["id"], ["map-role"])
        token = self.token()
        status, _ = call(self.base, "POST", "/admin/realms/" + REALM + "/users/" + human
                         + "/role-mappings/realm", [role], token)
        self.assertEqual(204, status)  # Native role mapping needs both component permissions.
        self.assertIn(role["id"], [value["id"] for value in self.admin("GET", "/users/" + human + "/role-mappings/realm")])
        self.admin("DELETE", user_permission)
        self.native_permission_paths.remove(user_permission)
        # Only the Roles component remains. The SMTP guard must still reject it.
        self.assert_native_grant_excludes_smtp(token)

    def assert_native_grant_excludes_smtp(self, token):
        before = self.admin("GET")["smtpServer"]
        self.assertEqual(403, self.smtp(PAYLOAD, proof(PAYLOAD), token=token)[0])
        self.assertEqual(before, self.admin("GET")["smtpServer"])
        # Privilege screening also denies metadata access; it cannot silently
        # publish a status that looks like the configuration command succeeded.
        self.assertEqual(403, self.smtp(context=proof({}, "SMTP_STATUS"), method="GET", token=token)[0])
        # Remove only installer-injected fixture grants, then use the public
        # status operation to prove denied control requests consumed no revision.
        for permission in self.native_permission_paths:
            self.admin("DELETE", permission)
        status, result = self.smtp(context=proof({}, "SMTP_STATUS"), method="GET", token=token)
        self.assertEqual(200, status)
        self.assertEqual({"revision": -1, "status": "NOT_APPLIED"}, result)

    def test_idempotent_revisions_and_stale_replay_cannot_reactivate_smtp(self):
        first_proof = proof(PAYLOAD)
        self.assertEqual(200, self.smtp(PAYLOAD, first_proof)[0])
        self.assertEqual(200, self.smtp(PAYLOAD, first_proof)[0])
        for body in (dict(PAYLOAD, globalSmtpHost="conflicting.fixture.internal"), dict(PAYLOAD, revision=0)):
            self.assertEqual(409, self.smtp(body, proof(body))[0])
        disabled = dict(PAYLOAD, revision=2, globalSmtpEnabled=False)
        status, result = self.smtp(disabled, proof(disabled))
        self.assertEqual(200, status)
        self.assertEqual({"revision": 2, "status": "DISABLED_OR_INCOMPLETE"}, result)
        self.assertEqual({}, self.admin("GET").get("smtpServer", {}))
        self.assertEqual(409, self.smtp(PAYLOAD, first_proof)[0])
        self.assertEqual({}, self.admin("GET").get("smtpServer", {}))

    def test_concurrent_first_revision_commands_have_one_winner_and_no_partial_write(self):
        token = self.token()
        candidates = [dict(PAYLOAD, globalSmtpHost=host) for host in ("one.fixture.internal", "two.fixture.internal")]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.smtp, body, proof(body), token=token) for body in candidates]
            results = [future.result() for future in futures]
        self.assertEqual([200, 409], sorted(result[0] for result in results))
        winner = candidates[next(index for index, result in enumerate(results) if result[0] == 200)]
        actual = self.admin("GET")
        self.assertEqual(winner["globalSmtpHost"], actual["smtpServer"]["host"])
        self.assertEqual("unchanged", actual["displayName"])
        status, result = self.smtp(context=proof({}, "SMTP_STATUS"), method="GET")
        self.assertEqual(200, status)
        self.assertEqual({"revision": 1, "status": "APPLIED"}, result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
