"""Actual ordinary human/session -> canonical machine maintenance HTTP diagnostic."""

import base64
import hashlib
import hmac
import json
import os
import platform
import subprocess
import time
import unittest
import uuid

from lifecycle_fixture import (
    ACTORS,
    CONTEXT_KEY,
    IMAGE,
    REALM,
    SUBJECTS,
    LifecycleFixture,
    call,
    canonical,
    mac,
)

ISSUER = "http://maintenance-human-fixture.invalid/realms/" + REALM
CLIENT = "ordinary-human-web"


class HumanMaintenanceFixture(LifecycleFixture):
    phase_receipts = []

    @classmethod
    def install_unused_readiness_profile(cls):
        return False

    @classmethod
    def extra_launch_arguments(cls):
        return []

    @classmethod
    def reviewed_self_operations(cls):
        return ["account.read", "account.locale", "account.profile", "account.password"]

    @classmethod
    def reviewed_human_profile(cls):
        return {
            "kind": "CONSULTANT", "group": "consultant",
            "roles": ["consultant", "group-chat-consultant"],
            "id": "consultant-v1",
        }

    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or os.environ.get("GITHUB_ACTIONS") != "true":
            raise AssertionError(
                "This bounded diagnostic requires the isolated Linux hosted job"
            )
        available = int(
            next(
                line.split()[1]
                for line in open("/proc/meminfo")
                if line.startswith("MemAvailable:")
            )
        )
        if available < 4 * 1024 * 1024:
            raise AssertionError(
                "Hosted native fixture requires four GiB headroom with two GiB reserve"
            )
        cls.phase_receipts = []
        cls.volume = "oriso-maintenance-human-" + uuid.uuid4().hex
        subprocess.run(
            [
                "docker",
                "volume",
                "create",
                "--label",
                "oriso-c-maintenance-human-test=true",
                cls.volume,
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        cls.addClassCleanup(
            lambda: subprocess.run(
                ["docker", "volume", "rm", cls.volume],
                check=True,
                capture_output=True,
                timeout=30,
            )
        )
        original = subprocess.run

        def launch(args, *a, **kw):
            if isinstance(args, list) and args[:2] == ["docker", "run"]:
                index = args.index(IMAGE)
                args[index:index] = [
                    "-v", cls.volume + ":/opt/keycloak/data", *cls.extra_launch_arguments()
                ]
                args.extend(["--hostname=http://maintenance-human-fixture.invalid"])
            return original(args, *a, **kw)

        subprocess.run = launch
        try:
            super().setUpClass()
        finally:
            subprocess.run = original
        helper = cls("runTest")
        LifecycleFixture.setUp(helper)
        cls.realm_id = helper.realm_id
        profile = helper.admin("GET", "/users/profile")
        profile["attributes"].append(
            {
                "name": "tenantId",
                "multivalued": False,
                "permissions": {"view": ["admin", "user"], "edit": ["admin"]},
                "validations": {"pattern": {"pattern": "0|[1-9][0-9]{0,18}"}},
            }
        )
        if not any(
            attribute["name"] == "locale" for attribute in profile["attributes"]
        ):
            profile["attributes"].append(
                {
                    "name": "locale",
                    "multivalued": False,
                    "permissions": {
                        "view": ["admin", "user"],
                        "edit": ["admin", "user"],
                    },
                    "validations": {"pattern": {"pattern": "de|fr|it"}},
                }
            )
        helper.admin("PUT", "/users/profile", profile)
        human_profile = cls.reviewed_human_profile()
        attempt, create = str(uuid.uuid4()), helper.creation(
            kind=human_profile["kind"], group=human_profile["group"]
        )
        status, opened = helper.request("create", attempt, create)
        helper.assertEqual(201, status)
        status, committed = helper.request(
            "commit", attempt, helper.finish(create, opened)
        )
        helper.assertEqual(200, status)
        helper.assertEqual("COMMITTED", committed["state"])
        cls.account_id, cls.creation_input = opened["accountId"], create
        mappers = [
            {
                "name": "subject",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-sub-mapper",
                "config": {"access.token.claim": "true"},
            },
            {
                "name": "roles",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-realm-role-mapper",
                "config": {
                    "claim.name": "realm_access.roles",
                    "access.token.claim": "true",
                    "multivalued": "true",
                    "jsonType.label": "String",
                },
            },
            {
                "name": "tenant",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-attribute-mapper",
                "config": {
                    "user.attribute": "tenantId",
                    "claim.name": "tenantId",
                    "access.token.claim": "true",
                    "jsonType.label": "String",
                },
            },
            {
                "name": "audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": "userservice",
                    "access.token.claim": "true",
                },
            },
        ]
        helper.admin(
            "POST",
            "/clients",
            {
                "clientId": CLIENT,
                "enabled": True,
                "publicClient": True,
                "protocol": "openid-connect",
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": True,
                "serviceAccountsEnabled": False,
                "fullScopeAllowed": False,
                "defaultClientScopes": [],
                "optionalClientScopes": [],
                "protocolMappers": mappers,
            },
        )
        from urllib.parse import urlencode

        client = helper.admin("GET", "/clients?" + urlencode({"clientId": CLIENT}))[0][
            "id"
        ]
        roles = [
            helper.admin("GET", "/roles/" + name)
            for name in human_profile["roles"]
        ]
        helper.admin("POST", "/clients/" + client + "/scope-mappings/realm", roles)
        cls.group = helper.admin(
            "GET", "/groups/" + helper.group_id("/human-roles/" + human_profile["group"])
        )
        native = {
            "realmId": cls.realm_id,
            "issuer": ISSUER,
            "clientIds": [CLIENT],
            "audienceSets": [["userservice"]],
            "technicalSubjects": sorted(SUBJECTS.values()),
            "technicalGroupIds": [
                helper.group_id("/protected-admins/technical-identities")
            ],
            "technicalRoles": sorted(
                {role for _, roles in ACTORS.values() for role in roles}
            ),
        }
        config = {
            "version": 1,
            "native": native,
            "ordinaryProfiles": [
                {
                    "id": human_profile["id"],
                    "version": 1,
                    "groupId": cls.group["id"],
                    "groupPath": "/human-roles/" + human_profile["group"],
                    "groupParentId": helper.group_id("/human-roles"),
                    "realmRoles": human_profile["roles"],
                    "clientRoles": {},
                    "allowUnassignedTenant": False,
                    "selfOperations": cls.reviewed_self_operations(),
                }
            ],
        }
        if cls.install_unused_readiness_profile():
            parent = helper.group_id("/human-roles")
            helper.admin("POST", "/groups/" + parent + "/children", {"name": "readiness-unused"})
            cls.unused_readiness_group = helper.group_id("/human-roles/readiness-unused")
            helper.admin("POST", "/groups/" + cls.unused_readiness_group + "/role-mappings/realm", roles)
            unused = dict(config["ordinaryProfiles"][0])
            unused.update(id="readiness-unused-v1", groupId=cls.unused_readiness_group,
                          groupPath="/human-roles/readiness-unused")
            config["ordinaryProfiles"].append(unused)
        helper.human()
        original(
            ["docker", "stop", "-t", "5", cls.name],
            check=True,
            capture_output=True,
            timeout=30,
        )
        original(
            ["docker", "rm", cls.name], check=True, capture_output=True, timeout=30
        )
        command = cls.command.copy()
        index = command.index(IMAGE)
        command[index:index] = [
            "-e",
            "ORISO_ACCOUNT_MAINTENANCE_CONFIG="
            + json.dumps(config, separators=(",", ":")),
        ]
        cls.configured_command = command.copy()
        original(command, check=True, capture_output=True, timeout=30)
        cls.refresh_endpoint("human-policy-restart")
        cls.ready()

    def setUp(self):
        self.ready()

    def phase(self, phase, **details):
        self.phase_receipts.append({"case": self.id(), "phase": phase, **details})

    def human(self):
        account = self.creation_input["account"]
        status, result = call(
            self.base,
            "POST",
            "/realms/" + REALM + "/protocol/openid-connect/token",
            {
                "client_id": CLIENT,
                "grant_type": "password",
                "username": account["username"],
                "password": account["password"],
                "scope": "openid",
            },
            form=True,
        )
        if status != 200:
            native = self.admin("GET", "/users/" + self.account_id)
            reasons = {
                "Account is not fully set up": "required-actions",
                "Invalid user credentials": "invalid-credentials",
                "Account disabled": "disabled",
            }
            self.phase(
                "human-login-failure",
                status=status,
                reason=reasons.get(result.get("error_description"), "other"),
                enabled=native.get("enabled") is True,
                profile_complete=all(
                    native.get(field) for field in ["username", "email", "firstName", "lastName"]
                ),
                required_actions_present=bool(native.get("requiredActions")),
            )
        self.assertEqual(200, status)
        bearer = result["access_token"]
        encoded = bearer.split(".")[1]
        claims = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        self.assertEqual(self.account_id, claims["sub"])
        self.assertEqual(ISSUER, claims["iss"])
        self.assertEqual(CLIENT, claims["azp"])
        self.assertEqual("11", claims["tenantId"])
        self.assertEqual(
            set(self.reviewed_human_profile()["roles"]),
            set(claims["realm_access"]["roles"]),
        )
        aud = claims["aud"]
        self.assertEqual({"userservice"}, set([aud] if isinstance(aud, str) else aud))
        native = self.admin("GET", "/users/" + self.account_id)
        self.assertTrue(native["enabled"])
        self.assertIsNone(native.get("serviceAccountClientLink"))
        current_roles = self.admin(
            "GET", "/users/" + self.account_id + "/role-mappings/realm/composite"
        )
        self.assertEqual(
            set(self.reviewed_human_profile()["roles"]),
            {role["name"] for role in current_roles},
        )
        groups = self.admin("GET", "/users/" + self.account_id + "/groups")
        self.assertEqual({self.group["id"]}, {group["id"] for group in groups})
        self.assertEqual(["11"], native["attributes"]["tenantId"])
        status, current = call(
            self.base,
            "GET",
            "/realms/" + REALM + "/protocol/openid-connect/userinfo",
            token=bearer,
        )
        self.assertEqual(200, status)
        self.assertEqual(self.account_id, current["sub"])
        self.assertGreater(claims["exp"], time.time())
        self.assertEqual(
            403,
            call(
                self.base,
                "GET",
                "/admin/realms/" + REALM + "/users/" + self.account_id,
                token=bearer,
            )[0],
        )
        self.assertTrue(claims.get("sid"))
        sessions = self.admin("GET", "/users/" + self.account_id + "/sessions")
        self.assertIn(claims["sid"], {session["id"] for session in sessions})
        self.phase(
            "human-native-preconditions",
            exact_subject=True,
            exact_issuer=True,
            exact_client=True,
            current_tenant=True,
            current_roles=True,
            live_session=True,
        )
        return bearer

    def replace_native_attributes(self, attributes):
        before = self.admin("GET", "/users/" + self.account_id)
        updated = dict(before)
        updated["attributes"] = attributes
        self.admin("PUT", "/users/" + self.account_id, updated)
        after = self.admin("GET", "/users/" + self.account_id)
        for field in ["username", "email", "firstName", "lastName", "enabled", "requiredActions"]:
            self.assertEqual(before.get(field), after.get(field))
        self.phase("installer-native-profile-preserved", profile_preserved=True)

    def invoke(self, command, body, human, expected):
        from urllib.error import HTTPError
        from urllib.request import Request, urlopen

        now = int(time.time())
        claims = {
            "iss": "userservice",
            "aud": "oriso-account-maintenance",
            "purpose": "ACCOUNT_MAINTENANCE",
            "operation": "account." + command,
            "method": "POST",
            "actor": "ACCOUNT_ADMIN",
            "realm": REALM,
            "target": "realm/" + self.realm_id + "/account/" + self.account_id,
            "taskClient": ACTORS["ACCOUNT_ADMIN"][0],
            "taskSubject": SUBJECTS["ACCOUNT_ADMIN"],
            "payloadDigest": mac("payload", body),
            "jti": str(uuid.uuid4()),
            "nonce": uuid.uuid4().hex,
            "iat": now,
            "exp": now + 60,
        }
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
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.token("ACCOUNT_ADMIN"),
            "X-ORISO-Task-Context": encoded + "." + signature,
        }
        if human is not None:
            headers["X-ORISO-Human-Authorization"] = "Bearer " + human
        request = Request(
            self.base
            + "/realms/"
            + REALM
            + "/oriso-account-maintenance/v1/accounts/"
            + self.account_id
            + "/"
            + command,
            data=canonical(body),
            method="POST",
            headers=headers,
        )
        try:
            with urlopen(request, timeout=30) as response:
                status, raw = response.status, response.read()
                self.last_response_no_store = "no-store" in response.headers.get("Cache-Control", "")
        except HTTPError as error:
            status, raw = error.code, error.read()
            self.last_response_no_store = "no-store" in error.headers.get("Cache-Control", "")
        value = json.loads(raw) if raw else None
        self.phase(
            "human-maintenance-http",
            command=command,
            status=status,
            expected_status=expected,
        )
        return status, value

class HumanMaintenance(HumanMaintenanceFixture, unittest.TestCase):
    def test_real_human_self_profile_is_receipt_bound_and_does_not_replay_over_later_edits(self):
        human = self.human()
        self.phase("ordinary-committed", create_status=201, commit_status=200)
        origin = {"kind": "SELF", "workflowId": str(uuid.uuid4()),
                  "humanSubject": self.account_id, "humanIssuer": ISSUER,
                  "humanClient": CLIENT, "humanAuthority": None}
        target = {"accountId": self.account_id, "tenantId": "11", "origin": origin}
        status, before = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        native = self.admin("GET", "/users/" + self.account_id)
        body = {"target": target, "operationId": str(uuid.uuid4()),
                "expectedState": before["state"],
                "change": {"firstName": "Updated", "lastName": "Ordinary", "email": native["email"]}}
        status, result = self.invoke("profile", body, human, 200)
        self.assertEqual(200, status)
        encoded = result["receipt"].split(".")[0]
        self.assertEqual(hmac.new(CONTEXT_KEY, ("maintenance-operation-receipt\n" + encoded).encode(), hashlib.sha256).hexdigest(), result["receipt"].split(".")[1])
        receipt = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        self.assertEqual("profile", receipt["command"])
        self.assertEqual(mac("maintenance-intent", body), receipt["intentDigest"])
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], receipt["ownerSubject"])
        updated = self.admin("GET", "/users/" + self.account_id)
        self.assertEqual("Updated", updated["firstName"])
        self.assertEqual("Ordinary", updated["lastName"])
        self.assertEqual(native["email"], updated["email"])
        updated["firstName"] = "Later installer edit"
        self.admin("PUT", "/users/" + self.account_id, updated)
        self.assertEqual((200, result), self.invoke("profile", body, human, 200))
        self.assertEqual("Later installer edit", self.admin("GET", "/users/" + self.account_id)["firstName"])
        changed = json.loads(json.dumps(body)); changed["change"]["firstName"] = "Conflicting"
        self.assertEqual(409, self.invoke("profile", changed, human, 409)[0])
        stale = json.loads(json.dumps(body)); stale["operationId"] = str(uuid.uuid4())
        self.assertEqual(409, self.invoke("profile", stale, human, 409)[0])
        # Same actual SELF boundary, now prove the credential effect and immutable retry.
        status, current = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        password = "Synthetic-" + uuid.uuid4().hex
        later_password = "Synthetic-later-" + uuid.uuid4().hex
        command = {"target": target, "operationId": str(uuid.uuid4()),
                   "expectedState": current["state"],
                   "change": {"password": password, "temporary": False}}
        def login(value):
            status, reply = call(self.base, "POST", "/realms/" + REALM + "/protocol/openid-connect/token",
                                 {"client_id": CLIENT, "grant_type": "password",
                                  "username": self.creation_input["account"]["username"],
                                  "password": value, "scope": "openid"}, form=True)
            if status != 200:
                self.assertEqual("invalid_grant", reply.get("error"))
                self.assertEqual("Invalid user credentials", reply.get("error_description"))
            return status
        self.assertEqual(200, login(self.creation_input["account"]["password"]))
        self.phase("human-password-proof-preconditions", original_password_verified=True,
                   exact_self_read=True, current_native_session=True)
        try:
            status, changed_password = self.invoke("password", command, human, 200)
            self.assertEqual(200, status)
            self.assertNotIn(password, canonical(changed_password).decode())
            encoded, signature = changed_password["receipt"].split(".")
            receipt_mac = hmac.compare_digest(signature, hmac.new(CONTEXT_KEY,
                ("maintenance-operation-receipt\n" + encoded).encode(), hashlib.sha256).hexdigest())
            receipt = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
            self.phase("human-password-receipt-comparison", mac_valid=receipt_mac,
                       command_matches=receipt.get("command") == "password",
                       intent_matches=receipt.get("intentDigest") == mac("maintenance-intent", command),
                       owner_matches=receipt.get("ownerSubject") == SUBJECTS["ACCOUNT_ADMIN"])
            self.assertTrue(receipt_mac)
            self.assertEqual("password", receipt["command"])
            self.assertEqual(mac("maintenance-intent", command), receipt["intentDigest"])
            self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], receipt["ownerSubject"])
            self.phase("human-password-receipt-verified", actual_admin_owner=True,
                       exact_original_intent=True, no_plaintext_password=True)
            new_login = login(password)
            original_login = login(self.creation_input["account"]["password"])
            self.phase("human-password-native-login", new_status=new_login, original_status=original_login)
            self.assertEqual(200, new_login)
            self.assertEqual(400, original_login)
            self.admin("PUT", "/users/" + self.account_id + "/reset-password",
                       {"type": "password", "value": later_password, "temporary": False})
            self.assertEqual((200, changed_password), self.invoke("password", command, human, 200))
            later_login, replayed_login = login(later_password), login(password)
            self.phase("human-password-native-retry-login", later_status=later_login, replayed_status=replayed_login)
            self.assertEqual(200, later_login)
            self.assertEqual(400, replayed_login)
            conflicting = json.loads(json.dumps(command))
            conflicting["change"]["password"] = "Synthetic-conflict-" + uuid.uuid4().hex
            self.assertEqual(409, self.invoke("password", conflicting, human, 409)[0])
        finally:
            self.admin("PUT", "/users/" + self.account_id + "/reset-password",
                       {"type": "password", "value": self.creation_input["account"]["password"],
                        "temporary": False})

    def test_real_human_self_locale_keeps_admin_receipt_owner_and_rejects_origin_mix(
        self,
    ):
        human = self.human()
        self.phase("ordinary-committed", create_status=201, commit_status=200)
        origin = {
            "kind": "SELF",
            "workflowId": str(uuid.uuid4()),
            "humanSubject": self.account_id,
            "humanIssuer": ISSUER,
            "humanClient": CLIENT,
            "humanAuthority": None,
        }
        target = {"accountId": self.account_id, "tenantId": "11", "origin": origin}
        status, before = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        body = {
            "target": target,
            "operationId": str(uuid.uuid4()),
            "expectedState": before["state"],
            "change": {"locale": "fr"},
        }
        before_audits = [
            event
            for event in self.admin("GET", "/admin-events?max=100")
            if event.get("resourcePath") == "accounts/" + self.account_id
            and event.get("operationType") == "UPDATE"
        ]
        status, result = self.invoke("locale", body, human, 200)
        self.assertEqual(200, status)
        encoded = result["receipt"].split(".")[0]
        receipt = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        self.assertEqual(
            hmac.new(
                CONTEXT_KEY,
                ("maintenance-operation-receipt\n" + encoded).encode(),
                hashlib.sha256,
            ).hexdigest(),
            result["receipt"].split(".")[1],
        )
        self.assertEqual(self.account_id, receipt["accountId"])
        self.assertEqual(body["operationId"], receipt["operationId"])
        self.assertEqual(self.realm_id, receipt["realmId"])
        self.assertEqual("locale", receipt["command"])
        self.assertEqual(before["state"], receipt["previousState"])
        self.assertEqual(mac("maintenance-intent", body), receipt["intentDigest"])
        self.assertEqual(mac("maintenance-origin", origin), receipt["originDigest"])
        self.assertEqual("11", receipt["tenantId"])
        self.assertEqual("UPDATED", receipt["result"])
        self.assertEqual(ACTORS["ACCOUNT_ADMIN"][0], receipt["ownerClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], receipt["ownerSubject"])
        self.assertFalse(human in json.dumps(result), "Human token must not enter result")
        audits = [
            event
            for event in self.admin("GET", "/admin-events?max=100")
            if event.get("resourcePath") == "accounts/" + self.account_id
            and event.get("operationType") == "UPDATE"
        ]
        # The earlier ordinary COMMIT legitimately has a CREATE-owned UPDATE at the same path.
        # Bind this one maintenance call by its exact added audit row, retaining all older rows.
        self.assertEqual(len(before_audits) + 1, len(audits))
        older = {canonical(event) for event in before_audits}
        added = [event for event in audits if canonical(event) not in older]
        self.assertEqual(1, len(added))
        self.assertEqual(SUBJECTS["ACCOUNT_ADMIN"], added[0]["authDetails"]["userId"])
        self.assertEqual(ACTORS["ACCOUNT_ADMIN"][0], added[0]["authDetails"]["clientId"])
        self.phase("human-maintenance-admin-audit", actual_admin_owner=True)
        self.assertEqual(
            ["fr"],
            self.admin("GET", "/users/" + self.account_id)["attributes"]["locale"],
        )
        attributes = self.admin("GET", "/users/" + self.account_id)["attributes"]
        attributes["locale"] = ["it"]
        self.replace_native_attributes(attributes)
        self.assertEqual((200, result), self.invoke("locale", body, human, 200))
        self.assertEqual(
            ["it"],
            self.admin("GET", "/users/" + self.account_id)["attributes"]["locale"],
        )
        mismatched = json.loads(json.dumps(target))
        mismatched["origin"]["humanClient"] = "foreign-client"
        self.assertEqual(
            403, self.invoke("read", {"target": mismatched}, human, 403)[0]
        )


    def test_real_human_locale_refusals_recheck_current_authority_and_frozen_intent(
        self,
    ):
        human = self.human()
        self.phase("ordinary-committed", create_status=201, commit_status=200)
        origin = {
            "kind": "SELF",
            "workflowId": str(uuid.uuid4()),
            "humanSubject": self.account_id,
            "humanIssuer": ISSUER,
            "humanClient": CLIENT,
            "humanAuthority": None,
        }
        target = {"accountId": self.account_id, "tenantId": "11", "origin": origin}
        self.assertEqual(401, self.invoke("read", {"target": target}, None, 401)[0])
        for field, value in [
            ("humanSubject", str(uuid.uuid4())),
            ("humanIssuer", "https://foreign.invalid/realms/foreign"),
            ("humanClient", "foreign-client"),
            ("humanAuthority", "PLATFORM"),
        ]:
            changed = json.loads(json.dumps(target))
            changed["origin"][field] = value
            self.assertEqual(403, self.invoke("read", {"target": changed}, human, 403)[0])
        changed = json.loads(json.dumps(target))
        changed["tenantId"] = "12"
        self.assertEqual(403, self.invoke("read", {"target": changed}, human, 403)[0])
        status, before = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        original = self.admin("GET", "/users/" + self.account_id)["attributes"]
        changed = json.loads(json.dumps(original))
        installer_locale = "it" if before["preferredLanguage"] != "it" else "de"
        changed["locale"] = [installer_locale]
        self.replace_native_attributes(changed)
        body = {
            "target": target,
            "operationId": str(uuid.uuid4()),
            "expectedState": before["state"],
            "change": {"locale": "fr"},
        }
        # A distinct installer effect must make the old state stale; never refresh it automatically.
        self.assertEqual(409, self.invoke("locale", body, human, 409)[0])
        self.assertEqual(
            [installer_locale],
            self.admin("GET", "/users/" + self.account_id)["attributes"]["locale"],
        )
        status, fresh = self.invoke("read", {"target": target}, human, 200)
        self.assertEqual(200, status)
        # An explicit new deliberate action allocates a new ID; the refused intent stays frozen.
        body["operationId"] = str(uuid.uuid4())
        body["expectedState"] = fresh["state"]
        self.assertEqual(200, self.invoke("locale", body, human, 200)[0])
        body["change"]["locale"] = "it"
        self.assertEqual(409, self.invoke("locale", body, human, 409)[0])
        self.assertEqual(
            ["fr"], self.admin("GET", "/users/" + self.account_id)["attributes"]["locale"]
        )
        # The still-valid JWT cannot preserve authority after current native tenant/grant changes.
        current = self.admin("GET", "/users/" + self.account_id)["attributes"]
        changed = json.loads(json.dumps(current))
        changed["tenantId"] = ["12"]
        self.replace_native_attributes(changed)
        try:
            self.assertEqual(403, self.invoke("read", {"target": target}, human, 403)[0])
        finally:
            self.replace_native_attributes(current)
        group_path = "/users/" + self.account_id + "/groups/" + self.group["id"]
        self.admin("DELETE", group_path)
        try:
            self.assertEqual(403, self.invoke("read", {"target": target}, human, 403)[0])
        finally:
            self.admin("PUT", group_path)
        self.assertEqual(200, self.invoke("read", {"target": target}, human, 200)[0])
        self.admin("POST", "/users/" + self.account_id + "/logout")
        self.assertEqual(401, self.invoke("read", {"target": target}, human, 401)[0])
