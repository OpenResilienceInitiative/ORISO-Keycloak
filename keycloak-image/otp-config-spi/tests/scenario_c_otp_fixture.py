#!/usr/bin/env python3
"""Real, isolated Keycloak HTTP proof of the opt-in C OTP receiver.

OTP_C_TEST_JAR must identify the locally packaged OTP SPI. Credentials and OTP
bodies are synthetic/in-memory only. LIFECYCLE_C_TEST_JAR supplies the actual
provided dependency; old native-power cases are negative contract controls.
Output contains test/status/hash evidence.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import hmac
import struct
import threading
import socketserver
import re
import sys
from email import policy as email_policy
from email.parser import BytesParser

import subprocess
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

IMAGE = "quay.io/keycloak/keycloak@sha256:9b0330756022422149aa6502eb2def8cd47c6e1b000c7c65cdb13e7c0133e992"
ROOT = Path(__file__).resolve().parents[3]
REALM = "scenario-c-otp-fixture"
CLIENT = "backend-account-admin"
SUBJECT = "3ba0a596-5d19-4d9c-ae86-78649a30b543"
ROLES = ["account-maintenance", "account-read", "otp-config-admin", "session-exchange"]
AUDIENCES = ["userservice", "oriso-otp"]
SECRET = "synthetic-otp-actor-secret-00000001"
INSTALLER = "synthetic-otp-installer-password-0001"


def call(base, method, path, body=None, token=None, form=False):
    headers = {
        "Content-Type": (
            "application/x-www-form-urlencoded" if form else "application/json"
        )
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    data = (
        None
        if body is None
        else (urlencode(body).encode() if form else json.dumps(body).encode())
    )
    try:
        with urlopen(
            Request(base + path, method=method, data=data, headers=headers), timeout=30
        ) as response:
            status, raw = response.status, response.read()
    except HTTPError as error:
        status, raw = error.code, error.read()
        error.close()
    return status, json.loads(raw) if raw else None


class MailSink(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.wfile.write(b"220 fixture SMTP ready\r\n")
            while True:
                line = self.rfile.readline()
                if not line:
                    return
                verb = line.split(b" ", 1)[0].strip().upper()
                if verb == b"DATA":
                    self.wfile.write(b"354 message\r\n")
                    body = []
                    while True:
                        line = self.rfile.readline()
                        if line in (b".\r\n", b"", b".\n"):
                            break
                        body.append(line)
                    self.server.messages.append(b"".join(body))
                    self.wfile.write(b"250 accepted\r\n")
                elif verb == b"QUIT":
                    self.wfile.write(b"221 bye\r\n")
                    return
                else:
                    self.wfile.write(b"250 accepted\r\n")


class ScenarioCOtpFixture:
    MODEL = "FIVE_ACTORS"
    phase_receipts = []

    @classmethod
    def setUpClass(cls):
        jar = Path(os.environ.get("OTP_C_TEST_JAR", ""))
        if not jar.is_file():
            raise AssertionError(
                "OTP_C_TEST_JAR must identify an existing packaged OTP SPI"
            )
        lifecycle = Path(os.environ.get("LIFECYCLE_C_TEST_JAR", ""))
        if not lifecycle.is_file():
            raise AssertionError("Actual provided lifecycle JAR is required")
        cls.phase_receipts = []
        cls.mail = MailSink(("0.0.0.0", 0), MailSink.Handler)
        cls.mail.messages = []
        threading.Thread(target=cls.mail.serve_forever, daemon=True).start()
        cls.addClassCleanup(cls.mail.server_close)
        cls.addClassCleanup(cls.mail.shutdown)
        cls.jar_sha256 = hashlib.sha256(jar.read_bytes()).hexdigest()
        cls.name = "oriso-c-otp-" + uuid.uuid4().hex[:10]
        command = [
            "docker",
            "run",
            "-d",
            "--name",
            cls.name,
            "--label",
            "oriso-c-otp-test=true",
            "--memory", "1g", "--cpus", "2",
            "-p",
            "127.0.0.1::8080",
            "-e",
            "JAVA_OPTS_APPEND=-XX:ActiveProcessorCount=2",
            "-e",
            "KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-installer",
            "-e",
            "KC_BOOTSTRAP_ADMIN_PASSWORD=" + INSTALLER,
            "-e",
            "ORISO_APP_BASE_URL=https://otp-fixture.internal",
            "-e",
            "EMAIL_BRANDING_NAME=OTP Fixture",
            "-e",
            "EMAIL_LEGAL_ORGANISATION_NAME=Fixture Operator",
            "-e",
            "TASK_IDENTITY_MODEL=" + (cls.MODEL or ""),
            "-e",
            "IDENTITY_ACCOUNT_ADMIN_CLIENT_ID=" + CLIENT,
            "-e",
            "IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT=" + SUBJECT,
            "-e", "ORISO_ACCOUNT_LIFECYCLE_ENABLED=" + ("true" if cls.MODEL else "false"),
            "-e", "ORISO_ACCOUNT_LIFECYCLE_REALM=" + REALM,
            "-e", "IDENTITY_ACCOUNT_CREATE_SERVICE_SUBJECT=00000000-0000-4000-8000-000000000001",
            "-e", "ORISO_TASK_CONTEXT_KEY=" + base64.b64encode(b"public-fixture-context-key-000001").decode(),
            "-e", "ORISO_ACCOUNT_LIFECYCLE_GROUPS=" + json.dumps({"/human-roles/consultant": ["consultant", "group-chat-consultant"]}),
            "-v", str(lifecycle.resolve()) + ":/opt/keycloak/providers/account-lifecycle-spi.jar:ro",
            "-v",
            str(jar.resolve()) + ":/opt/keycloak/providers/otp-config-spi.jar:ro",
            "-v",
            str(ROOT / "keycloak-image/themes/oriso")
            + ":/opt/keycloak/themes/oriso:ro",
            *(
                []
                if sys.platform == "darwin"
                else ["--add-host", "host.docker.internal:host-gateway"]
            ),
            IMAGE,
            "start-dev",
        ]
        subprocess.run(command, check=True, capture_output=True)
        cls.addClassCleanup(cls.stop)
        endpoint = (
            subprocess.run(
                ["docker", "port", cls.name, "8080/tcp"],
                check=True,
                capture_output=True,
                text=True,
            )
            .stdout.strip()
            .splitlines()[0]
        )
        cls.base = "http://" + endpoint
        deadline = time.monotonic() + 180
        while True:
            try:
                status, value = call(
                    cls.base,
                    "POST",
                    "/realms/master/protocol/openid-connect/token",
                    {
                        "client_id": "admin-cli",
                        "grant_type": "password",
                        "username": "synthetic-installer",
                        "password": INSTALLER,
                    },
                    form=True,
                )
                if status == 200:
                    cls.installer = value["access_token"]
                    return
            except (URLError, OSError, TimeoutError):
                pass
            if time.monotonic() > deadline:
                raise AssertionError("Isolated OTP Keycloak readiness failed")
            time.sleep(1)

    @classmethod
    def stop(cls):
        subprocess.run(
            ["docker", "rm", "-f", cls.name], check=True, capture_output=True
        )
        print("OTP SPI jar sha256:", cls.jar_sha256)

    def admin(self, method, path="", body=None):
        status, value = call(
            self.base, method, "/admin/realms/" + REALM + path, body, self.installer
        )
        self.assertLess(status, 300, (method, path, status))
        return value

    def setUp(self):
        client = {
            "clientId": CLIENT,
            "secret": SECRET,
            "protocol": "openid-connect",
            "enabled": True,
            "publicClient": False,
            "serviceAccountsEnabled": True,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "fullScopeAllowed": False,
            "defaultClientScopes": [],
            "optionalClientScopes": [],
            "protocolMappers": [
                {
                    "name": "actor-roles",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-realm-role-mapper",
                    "config": {
                        "claim.name": "realm_access.roles",
                        "access.token.claim": "true",
                        "multivalued": "true",
                        "jsonType.label": "String",
                    },
                },
                *(
                    {
                        "name": "audience-" + audience,
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": {
                            "included.custom.audience": audience,
                            "access.token.claim": "true",
                        },
                    }
                    for audience in AUDIENCES
                ),
            ],
        }
        groups = [
            {
                "name": "human-roles",
                "subGroups": [
                    {"name": "consultant", "realmRoles": ["consultant"]},
                    {
                        "name": "agency-admin",
                        "realmRoles": ["restricted-agency-admin", "user-admin"],
                    },
                ],
            },
            {
                "name": "protected-admins",
                "subGroups": [
                    {"name": "technical-identities"},
                    {"name": "platform-admins", "realmRoles": ["tenant-admin"]},
                ],
            },
        ]
        status, _ = call(
            self.base,
            "POST",
            "/admin/realms",
            {
                "realm": REALM,
                "enabled": True,
                "adminPermissionsEnabled": True,
                "emailTheme": "oriso",
                "smtpServer": {
                    "host": "host.docker.internal",
                    "port": str(self.mail.server_address[1]),
                    "from": "otp-fixture@oriso.org",
                    "auth": "false",
                    "ssl": "false",
                    "starttls": "false",
                },
                "clients": [client],
                "groups": groups,
                "roles": {
                    "realm": [
                        {"name": role}
                        for role in ROLES
                        + [
                            "consultant",
                            "tenant-admin",
                            "single-tenant-admin",
                            "restricted-agency-admin",
                            "user-admin",
                        ]
                    ]
                },
                "users": [
                    {
                        "id": SUBJECT,
                        "username": "service-account-" + CLIENT,
                        "enabled": True,
                        "serviceAccountClientId": CLIENT,
                    }
                ],
            },
            self.installer,
        )
        self.assertEqual(201, status)
        self.addCleanup(
            call, self.base, "DELETE", "/admin/realms/" + REALM, token=self.installer
        )
        self.client_id = self.admin(
            "GET", "/clients?" + urlencode({"clientId": CLIENT})
        )[0]["id"]
        self.assertEqual(
            SUBJECT,
            self.admin("GET", "/clients/" + self.client_id + "/service-account-user")[
                "id"
            ],
        )
        previous = self.admin("GET", "/users/" + SUBJECT + "/role-mappings/realm")
        if previous:
            self.admin("DELETE", "/users/" + SUBJECT + "/role-mappings/realm", previous)
        roles = [self.admin("GET", "/roles/" + role) for role in ROLES]
        self.admin("POST", "/users/" + SUBJECT + "/role-mappings/realm", roles)
        self.admin(
            "POST", "/clients/" + self.client_id + "/scope-mappings/realm", roles
        )
        self.technical = self.group_id("/protected-admins/technical-identities")
        self.admin("PUT", "/users/" + SUBJECT + "/groups/" + self.technical)
        self.ordinary = self.user("ordinary-consultant", ["/human-roles/consultant"])
        self.protected = self.user(
            "protected-platform", ["/protected-admins/platform-admins"]
        )
        self.centre = self.user("ordinary-centre-admin", ["/human-roles/agency-admin"])
        self.mail.messages.clear()
        self.unclassified = self.user("unclassified-human", [])
        self.policies()

    def group_id(self, path):
        return self.admin("GET", "/group-by-path/" + quote(path.lstrip("/"), safe="/"))[
            "id"
        ]

    def user(self, name, groups):
        self.admin(
            "POST",
            "/partialImport",
            {
                "ifResourceExists": "FAIL",
                "users": [{"username": name, "enabled": True, "groups": groups}],
            },
        )
        return self.admin(
            "GET", "/users?" + urlencode({"username": name, "exact": "true"})
        )[0]["id"]

    def policies(self):
        permissions = self.admin(
            "GET", "/clients?" + urlencode({"clientId": "admin-permissions"})
        )[0]["id"]
        base = "/clients/" + permissions + "/authz/resource-server"
        self.admin(
            "POST",
            base + "/policy/user",
            {"name": "ordinary-otp-manager", "users": [SUBJECT]},
        )
        self.admin(
            "POST", base + "/policy/user", {"name": "deny-protected", "users": []}
        )
        self.admin(
            "POST",
            base + "/permission/scope",
            {
                "name": "ordinary-otp-targets",
                "resourceType": "Groups",
                "resources": [
                    self.group_id("/human-roles"),
                    self.group_id("/human-roles/consultant"),
                    self.group_id("/human-roles/agency-admin"),
                ],
                "scopes": [
                    "view-members",
                    "manage-members",
                    "manage-membership-of-members",
                ],
                "policies": ["ordinary-otp-manager"],
            },
        )
        self.admin(
            "POST",
            base + "/permission/scope",
            {
                "name": "protected-otp-targets",
                "resourceType": "Groups",
                "resources": [self.group_id("/protected-admins")],
                "scopes": [
                    "view-members",
                    "manage-members",
                    "manage-membership-of-members",
                ],
                "policies": ["deny-protected"],
            },
        )

    def token(self, validate=True, client=CLIENT, secret=SECRET):
        status, value = call(
            self.base,
            "POST",
            "/realms/" + REALM + "/protocol/openid-connect/token",
            {
                "grant_type": "client_credentials",
                "client_id": client,
                "client_secret": secret,
            },
            form=True,
        )
        self.assertEqual(200, status)
        token = value["access_token"]
        if not validate:
            return token
        payload = token.split(".")[1]
        claims = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        self.assertEqual(CLIENT, claims["azp"])
        self.assertEqual(SUBJECT, claims["sub"])
        self.assertEqual(
            set(ROLES), set(claims.get("realm_access", {}).get("roles", []))
        )
        actual_aud = claims.get("aud", [])
        self.assertEqual(
            set(AUDIENCES),
            {actual_aud} if isinstance(actual_aud, str) else set(actual_aud),
        )
        self.assertFalse(claims.get("resource_access"))
        return token

    def otp(self, token, method, route, target, body=None):
        status, result = call(
            self.base,
            method,
            "/realms/" + REALM + "/otp-config/" + route + "/" + quote(target, safe=""),
            body,
            token,
        )
        self.phase_receipts.append({"case": self.id(), "phase": "original-otp-http",
                                    "method": method, "route": route, "status": status,
                                    "code_validation_rejected": status == 401 and isinstance(result, dict)
                                    and result.get("error") == "invalid_grant"})
        return status, result

    def credentials(self, user_id):
        return sorted(
            (c["id"], c["type"])
            for c in self.admin("GET", "/users/" + user_id + "/credentials")
        )

    def denied_routes(self, token, target, target_id=None):
        before = self.credentials(target_id) if target_id else None
        sent = len(self.mail.messages)
        for method, route, body in [
            ("GET", "fetch-otp-setup-info", None),
            (
                "PUT",
                "setup-otp",
                {"secret": "JBSWY3DPEHPK3PXP", "initialCode": "000000"},
            ),
            ("DELETE", "delete-otp", None),
            ("PUT", "send-verification-mail", {"email": "synthetic-target@oriso.org"}),
            ("POST", "setup-otp-mail", {"initialCode": "000000"}),
        ]:
            self.assertEqual(
                403, self.otp(token, method, route, target, body)[0], route
            )
        self.assertEqual(
            sent, len(self.mail.messages), "denied calls must not send mail"
        )
        if target_id:
            self.assertEqual(
                before,
                self.credentials(target_id),
                "denied calls must not change credentials",
            )

    def native_manage(self, token, user_id):
        return call(
            self.base,
            "PUT",
            "/admin/realms/" + REALM + "/users/" + user_id,
            {"firstName": "Native permitted"},
            token,
        )[0]

    def denied_prior_native_powers(self, target, user_id):
        token = self.token()
        encoded = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual(set(AUDIENCES), set(claims["aud"]))
        self.assertEqual(204, self.native_manage(token, user_id))
        self.phase_receipts.append({"case": self.id(), "phase": "prior-native-power-preconditions",
                                    "actual_two_audiences": True, "native_manage_status": 204,
                                    "no_scoped_proof_or_human_header": True})
        before, sent = self.credentials(user_id), len(self.mail.messages)
        seed = "JBSWY3DPEHPK3PXP"
        digest = hmac.new(seed.encode(), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
        offset = digest[-1] & 15
        code = str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)
        for method, route, body in [
            ("GET", "fetch-otp-setup-info", None),
            ("PUT", "setup-otp", {"secret": seed, "initialCode": code}),
            ("DELETE", "delete-otp", None),
            ("PUT", "send-verification-mail", {"email": "synthetic-target@oriso.org"}),
            ("POST", "setup-otp-mail", {"initialCode": "000000"}),
        ]:
            status, _ = self.otp(token, method, route, target, body)
            self.phase_receipts.append({"case": self.id(), "phase": "prior-native-power-http",
                                        "route": route, "method": method,
                                        "status": status, "expected_status": 403})
            with self.subTest(route=route):
                self.assertEqual(403, status)
        with self.subTest(postcondition="no-credential-effect"):
            self.assertEqual(before, self.credentials(user_id))
        with self.subTest(postcondition="no-mail-effect"):
            self.assertEqual(sent, len(self.mail.messages))

    def positive_protocol(self, target, user_id):
        token = self.token()
        self.assertEqual(204, self.native_manage(token, user_id))
        status, info = self.otp(token, "GET", "fetch-otp-setup-info", target)
        self.assertEqual(200, status)
        seed = info["otpSecret"]
        digest = hmac.new(
            seed.encode(), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1
        ).digest()
        offset = digest[-1] & 15
        code = str(
            (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000
        ).zfill(6)
        self.assertEqual(
            201,
            self.otp(
                token, "PUT", "setup-otp", target, {"secret": seed, "initialCode": code}
            )[0],
        )
        status, info = self.otp(token, "GET", "fetch-otp-setup-info", target)
        self.assertEqual(200, status)
        self.assertTrue(
            info["otpSetup"] and info["otpType"] == "APP", "app OTP should be active"
        )
        self.assertEqual(200, self.otp(token, "DELETE", "delete-otp", target)[0])
        self.assertEqual([], self.credentials(user_id))
        self.assertEqual(
            200,
            self.otp(
                token,
                "PUT",
                "send-verification-mail",
                target,
                {"email": "synthetic-target@oriso.org"},
            )[0],
        )
        self.assertTrue(
            bool(self.mail.messages), "verification email must reach isolated SMTP"
        )
        message = BytesParser(policy=email_policy.default).parsebytes(
            self.mail.messages[-1]
        )
        text = message.get_body(preferencelist=("plain",)).get_content()
        matches = re.findall(r"\b[0-9]{6}\b", text)
        self.assertTrue(bool(matches), "verification email must contain a code")
        status, result = self.otp(
            token, "POST", "setup-otp-mail", target, {"initialCode": matches[0]}
        )
        self.assertEqual(201, status)
        self.assertTrue(
            result.get("email") == "synthetic-target@oriso.org",
            "verified email retained",
        )
        status, info = self.otp(token, "GET", "fetch-otp-setup-info", target)
        self.assertEqual(200, status)
        self.assertTrue(
            info["otpSetup"] and info["otpType"] == "EMAIL", "mail OTP should be active"
        )
        self.assertEqual(200, self.otp(token, "DELETE", "delete-otp", target)[0])
        self.assertEqual([], self.credentials(user_id))

    def extra_permission(self, resource_type, target, scopes):
        cid = self.admin("GET", "/clients?clientId=admin-permissions")[0]["id"]
        base = "/clients/" + cid + "/authz/resource-server"
        created = self.admin(
            "POST",
            base + "/permission/scope",
            {
                "name": "unexpected-" + resource_type,
                "resourceType": resource_type,
                "resources": [target],
                "scopes": scopes,
                "policies": ["ordinary-otp-manager"],
            },
        )
        return base + "/policy/" + created["id"]

    def other_client(self, client_name):
        template = self.admin("GET", "/clients/" + self.client_id)
        for key in ("id", "registrationAccessToken"):
            template.pop(key, None)
        template["clientId"] = client_name
        for mapper in template["protocolMappers"]:
            mapper.pop("id", None)
        self.admin("POST", "/clients", template)
        cid = self.admin("GET", "/clients?" + urlencode({"clientId": client_name}))[0][
            "id"
        ]
        user = self.admin("GET", "/clients/" + cid + "/service-account-user")
        default_roles = self.admin(
            "GET", "/users/" + user["id"] + "/role-mappings/realm"
        )
        self.admin(
            "DELETE", "/users/" + user["id"] + "/role-mappings/realm", default_roles
        )
        roles = [self.admin("GET", "/roles/" + r) for r in ROLES]
        self.admin("POST", "/users/" + user["id"] + "/role-mappings/realm", roles)
        self.admin("POST", "/clients/" + cid + "/scope-mappings/realm", roles)
        self.admin("PUT", "/users/" + user["id"] + "/groups/" + self.technical)
        return cid, user["id"]

    def add_users_permission(self):
        permissions = self.admin(
            "GET", "/clients?" + urlencode({"clientId": "admin-permissions"})
        )[0]["id"]
        self.admin(
            "POST",
            "/clients/" + permissions + "/authz/resource-server/permission/scope",
            {
                "name": "hidden-users-target-grant",
                "resourceType": "Users",
                "resources": [self.unclassified],
                "scopes": ["manage", "view"],
                "policies": ["ordinary-otp-manager"],
            },
        )
