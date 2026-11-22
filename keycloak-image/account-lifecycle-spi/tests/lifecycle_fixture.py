#!/usr/bin/env python3
"""Disposable native lifecycle fixture. Synthetic credentials stay in memory."""

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

IMAGE = "quay.io/keycloak/keycloak@sha256:9b0330756022422149aa6502eb2def8cd47c6e1b000c7c65cdb13e7c0133e992"
REALM = "scenario-c-lifecycle-fixture"
INSTALLER = "synthetic-lifecycle-installer-password-0001"
CONTEXT_KEY = bytes(range(32))
ACTORS = {
    "SETUP": (
        "backend-setup",
        ["config-wizard", "invitation-reservations", "consultant-import"],
    ),
    "ACCOUNT_CREATE": (
        "backend-account-create",
        ["account-provisioning", "account-read"],
    ),
    "ACCOUNT_ADMIN": (
        "backend-account-admin",
        ["account-maintenance", "account-read", "otp-config-admin", "session-exchange"],
    ),
    "MAIL": (
        "backend-mail",
        [
            "smtp-sync",
            "system-email-delivery",
            "notification-dispatch",
            "notifications-technical",
        ],
    ),
    "RUNTIME": (
        "backend-runtime",
        [
            "runtime-policy",
            "matrix-agency",
            "matrix-agency-provision",
            "appointment-sync",
            "appointment-participant-cleanup",
        ],
    ),
}
SUBJECTS = {
    actor: str(uuid.uuid5(uuid.NAMESPACE_URL, "oriso-lifecycle-fixture/" + actor))
    for actor in ACTORS
}
HUMAN_GROUPS = {
    "user": ["user"],
    "consultant": ["consultant", "group-chat-consultant"],
    "agency-admin": ["restricted-agency-admin", "user-admin"],
    "consultant-agency-admin": [
        "consultant",
        "group-chat-consultant",
        "restricted-agency-admin",
        "user-admin",
    ],
}


def call(base, method, path, body=None, token=None, form=False, proof=None):
    headers = {
        "Content-Type": (
            "application/x-www-form-urlencoded" if form else "application/json"
        )
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    if proof:
        headers["X-ORISO-Task-Context"] = proof
    data = (
        None
        if body is None
        else (
            urlencode(body).encode()
            if form
            else body if isinstance(body, bytes) else json.dumps(body).encode()
        )
    )
    try:
        with urlopen(
            Request(base + path, method=method, data=data, headers=headers), timeout=30
        ) as response:
            status, raw = response.status, response.read()
    except HTTPError as error:
        status, raw = error.code, error.read()
        error.close()
    try:
        value = json.loads(raw) if raw else None
    except ValueError:
        value = None
    return status, value


class LifecycleFixture:
    ENABLED = True

    @classmethod
    def setUpClass(cls):
        jar = Path(os.environ.get("LIFECYCLE_C_TEST_JAR", ""))
        if not jar.is_file():
            raise AssertionError(
                "LIFECYCLE_C_TEST_JAR must identify an existing packaged provider"
            )
        cls.jar_path = jar.resolve()
        cls.jar_sha256 = hashlib.sha256(cls.jar_path.read_bytes()).hexdigest()
        cls.name = "oriso-c-lifecycle-" + uuid.uuid4().hex[:10]
        # Enable/configuration arguments are added after the neutral contract freezes.
        cls.command = [
            "docker",
            "run",
            "-d",
            "--name",
            cls.name,
            "--label",
            "oriso-c-lifecycle-test=true",
            "--memory",
            "1g",
            "--cpus",
            "2",
            "-p",
            "127.0.0.1::8080",
            "-e",
            "JAVA_OPTS_APPEND=-Xms128m -Xmx512m -XX:ActiveProcessorCount=2",
            "-e",
            "KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-installer",
            "-e",
            "KC_BOOTSTRAP_ADMIN_PASSWORD=" + INSTALLER,
            "-e",
            "TASK_IDENTITY_MODEL=FIVE_ACTORS",
            "-e",
            "ORISO_ACCOUNT_LIFECYCLE_ENABLED=" + str(cls.ENABLED).lower(),
            "-e",
            "ORISO_ACCOUNT_LIFECYCLE_REALM=" + REALM,
            "-e",
            "IDENTITY_ACCOUNT_CREATE_SERVICE_SUBJECT=" + SUBJECTS["ACCOUNT_CREATE"],
            "-e",
            "IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT=" + SUBJECTS["ACCOUNT_ADMIN"],
            "-e",
            "ORISO_TASK_CONTEXT_KEY=" + base64.b64encode(CONTEXT_KEY).decode(),
            "-e",
            "ORISO_IDENTITY_DUMMY_EMAIL_SUFFIX=@lifecycle-fixture.invalid",
            "-e",
            "ORISO_ACCOUNT_LIFECYCLE_GROUPS="
            + json.dumps(
                {"/human-roles/" + k: v for k, v in HUMAN_GROUPS.items()},
                separators=(",", ":"),
            ),
            "-v",
            str(jar.resolve())
            + ":/opt/keycloak/providers/account-lifecycle-spi.jar:ro",
            IMAGE,
            "start-dev",
        ]
        subprocess.run(cls.command, check=True, capture_output=True)
        cls.addClassCleanup(cls.stop)
        if hashlib.sha256(cls.jar_path.read_bytes()).hexdigest() != cls.jar_sha256:
            raise AssertionError("Native provider changed during container bind")
        cls.endpoint_receipts = []
        cls.refresh_endpoint("initial")
        cls.ready()

    @classmethod
    def refresh_endpoint(cls, phase):
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
        previous = getattr(cls, "base", None)
        cls.base = "http://" + endpoint
        receipt = {
            "phase": phase,
            "before": previous,
            "after": cls.base,
            "changed": previous != cls.base,
        }
        cls.endpoint_receipts.append(receipt)
        print("Lifecycle endpoint receipt:", json.dumps(receipt, sort_keys=True))

    @classmethod
    def ready(cls):
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
            running = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", cls.name],
                capture_output=True,
                text=True,
            )
            if running.returncode != 0 or running.stdout.strip() != "true":
                raise AssertionError(
                    "Owned lifecycle Keycloak exited before readiness; protected logs retained"
                )
            if time.monotonic() > deadline:
                raise AssertionError("Isolated lifecycle Keycloak readiness failed")
            time.sleep(1)

    @classmethod
    def stop(cls):
        private = os.environ.get("LIFECYCLE_C_PRIVATE_LOG_DIR")
        if private:
            folder = Path(private)
            if folder.is_dir() and folder.stat().st_mode & 0o077 == 0:
                log = folder / (cls.name + ".log")
                with log.open("wb") as output:
                    log.chmod(0o600)
                    subprocess.run(
                        ["docker", "logs", cls.name],
                        stdout=output,
                        stderr=subprocess.STDOUT,
                        check=False,
                    )
        subprocess.run(
            ["docker", "rm", "-f", cls.name], check=True, capture_output=True
        )
        if hashlib.sha256(cls.jar_path.read_bytes()).hexdigest() != cls.jar_sha256:
            raise AssertionError("Native provider changed during execution")
        print("Lifecycle provider jar sha256:", cls.jar_sha256)

    def admin(self, method, path="", body=None):
        status, value = call(
            self.base, method, "/admin/realms/" + REALM + path, body, self.installer
        )
        self.assertLess(status, 300, (method, path, status))
        return value

    def group_id(self, path):
        return self.admin("GET", "/group-by-path/" + quote(path.lstrip("/"), safe="/"))[
            "id"
        ]

    def token(self, actor="ACCOUNT_CREATE"):
        client, roles = ACTORS[actor]
        status, result = call(
            self.base,
            "POST",
            "/realms/" + REALM + "/protocol/openid-connect/token",
            {
                "client_id": client,
                "client_secret": "synthetic-lifecycle-" + actor,
                "grant_type": "client_credentials",
            },
            form=True,
        )
        self.assertEqual(200, status)
        bearer = result["access_token"]
        encoded = bearer.split(".")[1]
        claims = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        self.assertEqual(client, claims["azp"])
        self.assertEqual(SUBJECTS[actor], claims["sub"])
        self.assertEqual(
            set(roles), set(claims.get("realm_access", {}).get("roles", []))
        )
        self.assertFalse(claims.get("resource_access"))
        return bearer

    def setUp(self):
        clients = []
        for actor, (name, roles) in ACTORS.items():
            audiences = ["userservice", "oriso-account-lifecycle"] + (
                ["oriso-otp"] if actor == "ACCOUNT_ADMIN" else []
            )
            clients.append(
                {
                    "clientId": name,
                    "secret": "synthetic-lifecycle-" + actor,
                    "enabled": True,
                    "protocol": "openid-connect",
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
                        *[
                            {
                                "name": "audience-" + aud,
                                "protocol": "openid-connect",
                                "protocolMapper": "oidc-audience-mapper",
                                "config": {
                                    "included.custom.audience": aud,
                                    "access.token.claim": "true",
                                },
                            }
                            for aud in audiences
                        ],
                    ],
                }
            )
        role_names = (
            set(r for _, roles in ACTORS.values() for r in roles)
            | set(r for roles in HUMAN_GROUPS.values() for r in roles)
            | {"tenant-admin"}
        )
        status, _ = call(
            self.base,
            "POST",
            "/admin/realms",
            {
                "realm": REALM,
                "enabled": True,
                "adminPermissionsEnabled": True,
                "adminEventsEnabled": True,
                "adminEventsDetailsEnabled": False,
                "clients": clients,
                "groups": [
                    {
                        "name": "human-roles",
                        "subGroups": [
                            {"name": k, "realmRoles": v}
                            for k, v in HUMAN_GROUPS.items()
                        ],
                    },
                    {"name": "pending-provisioning"},
                    {
                        "name": "protected-admins",
                        "subGroups": [
                            {"name": "technical-identities"},
                            {"name": "platform-admins", "realmRoles": ["tenant-admin"]},
                        ],
                    },
                ],
                "roles": {"realm": [{"name": r} for r in role_names]},
                "users": [
                    {
                        "id": SUBJECTS[a],
                        "username": "service-account-" + n,
                        "enabled": True,
                        "serviceAccountClientId": n,
                    }
                    for a, (n, _) in ACTORS.items()
                ],
            },
            self.installer,
        )
        self.assertEqual(201, status)
        self.addCleanup(
            lambda: call(
                self.base, "DELETE", "/admin/realms/" + REALM, token=self.installer
            )
        )
        self.realm_id = self.admin("GET")["id"]
        self.client_ids = {}
        for actor, (name, roles) in ACTORS.items():
            cid = self.admin("GET", "/clients?" + urlencode({"clientId": name}))[0][
                "id"
            ]
            self.client_ids[actor] = cid
            old = self.admin(
                "GET", "/users/" + SUBJECTS[actor] + "/role-mappings/realm"
            )
            if old:
                self.admin(
                    "DELETE", "/users/" + SUBJECTS[actor] + "/role-mappings/realm", old
                )
            mapped = [self.admin("GET", "/roles/" + role) for role in roles]
            self.admin(
                "POST", "/users/" + SUBJECTS[actor] + "/role-mappings/realm", mapped
            )
            self.admin("POST", "/clients/" + cid + "/scope-mappings/realm", mapped)
            self.admin(
                "PUT",
                "/users/"
                + SUBJECTS[actor]
                + "/groups/"
                + self.group_id("/protected-admins/technical-identities"),
            )
        # New users must start without implicit realm/client default privileges.
        realm = self.admin("GET")
        default = realm["defaultRole"]["name"]
        inherited = self.admin("GET", "/roles/" + default + "/composites")
        if inherited:
            self.admin("DELETE", "/roles/" + default + "/composites", inherited)

    def request(
        self,
        command,
        attempt,
        body,
        actor="ACCOUNT_CREATE",
        proof_changes=None,
        bearer=None,
        wire_body=None,
    ):
        method = "PUT" if command == "create" else "POST"
        operation = {
            "create": "account.create",
            "owned-read": "account.owned-read",
            "recover": "account.creation-recover",
            "commit": "account.commit",
            "compensate": "account.compensate",
        }[command]
        now = int(time.time())
        claims = {
            "iss": "userservice",
            "aud": "oriso-account-lifecycle",
            "purpose": (
                "ACCOUNT_MAINTENANCE"
                if actor == "ACCOUNT_ADMIN"
                else "ACCOUNT_PROVISIONING"
            ),
            "operation": operation,
            "method": method,
            "actor": actor,
            "realm": REALM,
            "target": "realm/" + self.realm_id + "/account-attempt/" + attempt,
            "taskClient": ACTORS[actor][0],
            "taskSubject": SUBJECTS[actor],
            "payloadDigest": mac("payload", body),
            "jti": str(uuid.uuid4()),
            "nonce": uuid.uuid4().hex,
            "iat": now,
            "exp": now + 60,
        }
        claims.update(proof_changes or {})
        encoded = base64.urlsafe_b64encode(canonical(claims)).decode().rstrip("=")
        signature = (
            base64.urlsafe_b64encode(
                hmac.new(
                    CONTEXT_KEY, ("proof\n" + encoded).encode(), hashlib.sha256
                ).digest()
            )
            .decode()
            .rstrip("=")
        )
        suffix = "" if command == "create" else "/" + command
        return call(
            self.base,
            method,
            "/realms/"
            + REALM
            + "/oriso-account-lifecycle/v1/attempts/"
            + attempt
            + suffix,
            body if wire_body is None else wire_body,
            bearer or self.token(actor),
            proof=encoded + "." + signature,
        )

    def creation(self, kind="CONSULTANT", group="consultant", origin="HUMAN_ADMIN"):
        scope = {
            "tenantId": "11",
            "registrationKind": kind,
            "initialGroup": "/human-roles/" + group,
            "origin": {
                "kind": origin,
                "workflowId": str(uuid.uuid4()),
                "provenance": "verified-fixture-origin",
                "humanIssuer": "https://fixture-human.invalid/realms/fixture",
                "humanSubject": "verified-human",
                "humanAuthority": "user-admin",
                "agencyIds": ["27"],
            },
        }
        account = {
            "username": "lifecycle-" + uuid.uuid4().hex,
            "email": "synthetic-" + uuid.uuid4().hex + "@oriso.org",
            "firstName": "Synthetic",
            "lastName": "Fixture",
            "preferredLanguage": "de",
            "password": "Synthetic-lifecycle-password-0001",
            "passwordTemporary": False,
        }
        return {
            "identity": {
                "scope": scope,
                "creationFingerprint": mac(
                    "creation-payload", {"scope": scope, "account": account}
                ),
            },
            "execution": {"executionId": str(uuid.uuid4()), "generation": 0},
            "account": account,
        }

    def finish(self, create, result, cleanup=False):
        return {
            "identity": create["identity"],
            "execution": result["execution"],
            "accountId": result["accountId"],
            "creationProof": result["creationProof"],
            "localCleanup" if cleanup else "localCommit": {
                "journalVersion": 1,
                "outboxId": str(uuid.uuid4()),
                "effectsDigest": "a" * 64,
            },
        }


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def mac(domain, value):
    return hmac.new(
        CONTEXT_KEY, (domain + "\n").encode() + canonical(value), hashlib.sha256
    ).hexdigest()
