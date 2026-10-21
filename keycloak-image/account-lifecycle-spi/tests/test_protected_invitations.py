#!/usr/bin/env python3
"""Protected receiving HTTP seam. Synthetic fixture; missing setup is an error."""

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from lifecycle_fixture import (
    LifecycleFixture,
    ACTORS,
    SUBJECTS,
    REALM,
    INSTALLER,
    call,
)
from protected_resources import HOSTED_PROFILE, require_start, require_active

HUMAN = None  # Set only from the actual native user lookup, never a proposed UUID.
ISSUER = "http://protected-fixture.invalid/realms/" + REALM
HUMAN_PASSWORD = "synthetic-human-password-0001"


class ProtectedInvitations(LifecycleFixture, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global HUMAN
        cls.preconditions = []
        cls.configuration_checked = False
        cls.approval_observation = None
        cls.native_image_ids = []
        cls.setup_precondition = None
        cls.phase = "initial-native-start"
        # Two finite boots: existing installer builds real native state; provider then
        # starts with privileged exact IDs over that same persisted native database.
        cls.native_volume = None
        cls.data = None
        if os.environ.get("PROTECTED_PROOF_RESOURCE_PROFILE") == HOSTED_PROFILE:
            # Docker owns the Linux data directory, including uid1000 H2 files;
            # a labelled volume avoids unsafe sudo/chown or host cleanup bypasses.
            require_start()
            cls.native_volume = "oriso-protected-h2-" + uuid.uuid4().hex
            subprocess.run(
                [
                    "docker",
                    "volume",
                    "create",
                    "--label",
                    "oriso-protected-receiver-test=true",
                    cls.native_volume,
                ],
                check=True,
                capture_output=True,
                timeout=30,
            )
            cls.addClassCleanup(cls.remove_owned_volume)
            cls.data_mount = cls.native_volume + ":/opt/keycloak/data"
        else:
            cls.data = Path(tempfile.mkdtemp(prefix="oriso-protected-native-"))
            cls.data.chmod(0o777)
            cls.addClassCleanup(lambda: shutil.rmtree(cls.data))
            cls.data_mount = str(cls.data) + ":/opt/keycloak/data"
        original_run = subprocess.run

        def launch(args, *a, **kw):
            if isinstance(args, list) and args[:2] == ["docker", "run"]:
                cls.memoryStart()
                image_index = args.index(
                    "quay.io/keycloak/keycloak@sha256:9b0330756022422149aa6502eb2def8cd47c6e1b000c7c65cdb13e7c0133e992"
                )
                args[image_index:image_index] = [
                    "--label",
                    "oriso-protected-receiver-test=true",
                    "-v",
                    cls.data_mount,
                ]
                args.extend(["--hostname=http://protected-fixture.invalid"])
            return original_run(args, *a, **kw)

        # This scoped launcher substitution only adds the owned persistence mount;
        # restore before any native request or second launch.
        subprocess.run = launch
        try:
            super().setUpClass()
        finally:
            subprocess.run = original_run
        cls.phase = "seed-native-realm"
        helper = cls("runTest")
        helper.setUpNativeRealm()
        cls.realm_id = helper.realm_id
        cls.client_ids = helper.client_ids
        cls.protected_group_id = helper.group_id("/protected-admins/platform-admins")
        technical_group = helper.group_id("/protected-admins/technical-identities")
        # Existing one-off installer establishes a named application human. It is
        # separate from approve and never uses an installer token for approve.
        helper.admin(
            "POST",
            "/users",
            {
                "username": "reviewed-human",
                "enabled": True,
                "email": "reviewed-human@fixture.invalid",
                "emailVerified": True,
                "firstName": "Reviewed",
                "lastName": "Human",
                "attributes": {"tenantId": ["0"]},
                "credentials": [
                    {"type": "password", "value": HUMAN_PASSWORD, "temporary": False}
                ],
            },
        )
        humans = helper.admin("GET", "/users?username=reviewed-human&exact=true")
        helper.assertEqual(1, len(humans))
        HUMAN = humans[0]["id"]
        helper.assertEqual(HUMAN, str(uuid.UUID(HUMAN)))
        helper.admin("POST", "/roles", {"name": "agency-admin"})
        roles = [
            helper.admin("GET", "/roles/" + r) for r in ["agency-admin", "tenant-admin"]
        ]
        helper.admin("POST", "/users/" + HUMAN + "/role-mappings/realm", roles)
        helper.admin(
            "POST",
            "/groups/" + cls.protected_group_id + "/role-mappings/realm",
            roles,
        )
        default = helper.admin("GET", "/users/" + HUMAN + "/role-mappings/realm")
        defaults = [
            r for r in default if r["name"] not in ["agency-admin", "tenant-admin"]
        ]
        if defaults:
            helper.admin("DELETE", "/users/" + HUMAN + "/role-mappings/realm", defaults)
        helper.admin(
            "POST",
            "/clients",
            {
                "clientId": "protected-human-web",
                "enabled": True,
                "publicClient": True,
                "protocol": "openid-connect",
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": True,
                "serviceAccountsEnabled": False,
                "fullScopeAllowed": False,
                "defaultClientScopes": [],
                "optionalClientScopes": [],
                "protocolMappers": [
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
                ],
            },
        )
        client = helper.admin("GET", "/clients?clientId=protected-human-web")[0]["id"]
        helper.admin("POST", "/clients/" + client + "/scope-mappings/realm", roles)
        setup_audiences = [
            "agencyservice",
            "consultingtypeservice",
            "tenantservice",
            "userservice",
        ]
        setup_mapper_base = (
            "/clients/" + helper.client_ids["SETUP"] + "/protocol-mappers/models"
        )
        for mapper in helper.admin("GET", setup_mapper_base):
            if mapper["protocolMapper"] == "oidc-audience-mapper":
                helper.admin("DELETE", setup_mapper_base + "/" + mapper["id"])
        for audience in setup_audiences:
            helper.admin(
                "POST",
                setup_mapper_base,
                {
                    "name": "audience-" + audience,
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {
                        "included.custom.audience": audience,
                        "access.token.claim": "true",
                    },
                },
            )
        setup_bearer = helper.token("SETUP")
        encoded = setup_bearer.split(".")[1]
        setup_claims = json.loads(
            base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        )
        setup_aud = setup_claims["aud"]
        helper.assertEqual(
            set(setup_audiences),
            set([setup_aud] if isinstance(setup_aud, str) else setup_aud),
        )
        cls.setup_precondition = {
            "nativeSubjectMatched": True,
            "exactRoleUnionMatched": True,
            "audiences": setup_audiences,
        }
        # Prove complete native human/token/session preconditions on the seed
        # boot before spending the protected restart budget.
        helper.human()
        configuration = {
            "realmId": cls.realm_id,
            "realmName": REALM,
            "issuer": ISSUER,
            "technicalSubjects": sorted(SUBJECTS.values()),
            "technicalGroupIds": [technical_group],
            "technicalRoles": sorted({r for _, rr in ACTORS.values() for r in rr}),
            "actorSubjects": SUBJECTS,
            "machineAudienceSets": {
                "SETUP": setup_audiences,
                "ACCOUNT_CREATE": ["oriso-account-lifecycle", "userservice"],
                "ACCOUNT_ADMIN": [
                    "oriso-account-lifecycle",
                    "oriso-otp",
                    "userservice",
                ],
            },
            "bindings": [
                {
                    "subject": HUMAN,
                    "authority": "PLATFORM",
                    "authorizerTenantIds": [0],
                    "humanClientIds": ["protected-human-web"],
                    "audienceSets": [["userservice"]],
                    "protectedProfileIds": ["platform-v1"],
                    "realmRoles": ["agency-admin", "tenant-admin"],
                    "clientRoles": {},
                    "version": 1,
                }
            ],
            "profiles": [
                {
                    "id": "platform-v1",
                    "version": 1,
                    "kind": "PLATFORM_ADMIN",
                    "tenantModes": ["EXISTING"],
                    "groupId": cls.protected_group_id,
                    "groupPath": "/protected-admins/platform-admins",
                    "realmRoles": ["agency-admin", "tenant-admin"],
                    "clientRoles": {},
                    "usernamePolicy": "USERNAME_TRANSCODER_V1",
                    "firstNamePolicy": "INVITE_WITH_EMAIL_LOCAL_PART_FALLBACK",
                    "lastNamePolicy": "INVITE_WITH_ADMIN_FALLBACK",
                }
            ],
        }
        original_run(
            ["docker", "stop", "-t", "5", cls.name], check=True, capture_output=True
        )
        original_run(["docker", "rm", cls.name], check=True, capture_output=True)
        command = cls.command.copy()
        index = command.index(
            "quay.io/keycloak/keycloak@sha256:9b0330756022422149aa6502eb2def8cd47c6e1b000c7c65cdb13e7c0133e992"
        )
        command[index:index] = [
            "-e",
            "ORISO_PROTECTED_INVITATIONS_ENABLED=true",
            "-e",
            "ORISO_PROTECTED_INVITATIONS_CONFIG="
            + json.dumps(configuration, separators=(",", ":")),
        ]
        cls.phase = "configured-native-restart"
        cls.memoryStart()
        original_run(command, check=True, capture_output=True)
        cls.refresh_endpoint("protected-enabled-restart")
        cls.ready()
        installed = json.loads(
            original_run(
                ["docker", "inspect", "--format", "{{json .Config.Env}}", cls.name],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        installed_values = dict(value.split("=", 1) for value in installed)
        helper.assertTrue(
            all(
                installed_values.get(key) == value
                for key, value in {
                    "ORISO_PROTECTED_INVITATIONS_ENABLED": "true",
                    "ORISO_ACCOUNT_LIFECYCLE_ENABLED": "true",
                    "TASK_IDENTITY_MODEL": "FIVE_ACTORS",
                }.items()
            ),
            "Native fixture enable/model configuration mismatch",
        )
        protected_config = next(
            v.split("=", 1)[1]
            for v in installed
            if v.startswith("ORISO_PROTECTED_INVITATIONS_CONFIG=")
        )
        helper.assertTrue(
            json.loads(protected_config) == configuration,
            "Native fixture privileged configuration mismatch",
        )
        cls.configuration_checked = True
        cls.phase = "configured-native-ready"

    @classmethod
    def remove_owned_volume(cls):
        owned = subprocess.run(
            [
                "docker",
                "volume",
                "inspect",
                "--format",
                '{{ index .Labels "oriso-protected-receiver-test" }}',
                cls.native_volume,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        if owned != "true":
            raise AssertionError("Owned native volume label mismatch")
        subprocess.run(
            ["docker", "volume", "rm", cls.native_volume],
            check=True,
            capture_output=True,
            timeout=30,
        )

    @classmethod
    def memoryStart(cls):
        require_start()

    @classmethod
    def ready(cls):
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            require_active("native-readiness")
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
                    image_id = subprocess.run(
                        ["docker", "inspect", "--format", "{{.Image}}", cls.name],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    ).stdout.strip()
                    if not image_id.startswith("sha256:") or len(image_id) != 71:
                        raise AssertionError("Actual native image ID unavailable")
                    cls.native_image_ids.append(image_id)
                    return
            except (OSError, TimeoutError):
                pass
            state = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", cls.name],
                capture_output=True,
                text=True,
            )
            if state.returncode or state.stdout.strip() != "true":
                raise AssertionError(
                    "Protected owned container exited before readiness"
                )
            time.sleep(1)
        raise AssertionError("Protected readiness300s expired")

    def setUpNativeRealm(self):
        super().setUp()
        # Do not run base per-test realm deletion while the persistent fixture is live.
        self._cleanups.clear()

    def setUp(self):
        pass

    def human(self):
        require_active("human-preconditions")
        type(self).phase = "human-preconditions"
        status, value = call(
            self.base,
            "POST",
            "/realms/" + REALM + "/protocol/openid-connect/token",
            {
                "client_id": "protected-human-web",
                "grant_type": "password",
                "username": "reviewed-human",
                "password": HUMAN_PASSWORD,
                "scope": "openid",
            },
            form=True,
        )
        self.assertEqual(200, status)
        bearer = value["access_token"]
        payload = bearer.split(".")[1]
        claims = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        self.assertEqual(HUMAN, claims["sub"])
        self.assertEqual(ISSUER, claims["iss"])
        self.assertEqual("protected-human-web", claims["azp"])
        self.assertEqual("0", claims["tenantId"])
        audiences = claims["aud"]
        self.assertEqual(
            {"userservice"},
            set([audiences] if isinstance(audiences, str) else audiences),
        )
        clients = self.admin("GET", "/clients?clientId=protected-human-web")
        self.assertEqual(1, len(clients))
        client = self.admin("GET", "/clients/" + clients[0]["id"])
        self.assertTrue(client["enabled"])
        self.assertTrue(client["standardFlowEnabled"])
        self.assertFalse(client["serviceAccountsEnabled"])
        self.assertFalse(client["fullScopeAllowed"])
        native = self.admin("GET", "/users/" + HUMAN)
        self.assertTrue(native["enabled"])
        self.assertIsNone(native.get("serviceAccountClientLink"))
        self.assertEqual(
            {"agency-admin", "tenant-admin"}, set(claims["realm_access"]["roles"])
        )
        native_roles = self.admin(
            "GET", "/users/" + HUMAN + "/role-mappings/realm/composite"
        )
        self.assertEqual(
            {"agency-admin", "tenant-admin"}, {role["name"] for role in native_roles}
        )
        self.assertEqual([], self.admin("GET", "/users/" + HUMAN + "/groups"))
        mappings = self.admin("GET", "/users/" + HUMAN + "/role-mappings")
        self.assertFalse(mappings.get("clientMappings"))
        self.assertGreater(claims["exp"], time.time())
        status, current = call(
            self.base,
            "GET",
            "/realms/" + REALM + "/protocol/openid-connect/userinfo",
            token=bearer,
        )
        self.assertEqual(200, status)
        self.assertEqual(HUMAN, current["sub"])
        self.assertTrue(claims.get("sid"))
        self.assertTrue(
            any(
                session["id"] == claims["sid"]
                for session in self.admin("GET", "/users/" + HUMAN + "/sessions")
            )
        )
        type(self).preconditions.append(
            {
                "stage": "configured" if type(self).configuration_checked else "seed",
                "realmId": self.realm_id,
                "subject": HUMAN,
                "issuer": ISSUER,
                "clientId": "protected-human-web",
                "audiences": ["userservice"],
                "tenantId": 0,
                "realmRoles": ["agency-admin", "tenant-admin"],
                "clientRoles": {},
                "enabledNativeUser": True,
                "enabledInteractiveClient": True,
                "serviceAccountLinkAbsent": True,
                "currentNativeSession": True,
                "nativeUserinfoValidatedToken": True,
                "actualCanonicalSubject": True,
            }
        )
        return bearer

    def scope(self):
        return {
            "workflowId": str(uuid.uuid4()),
            "inviteId": str(uuid.uuid4()),
            "authorizationRevision": 1,
            "purpose": "INVITE",
            "recipient": "invite-" + uuid.uuid4().hex + "@fixture.invalid",
            "protectedKind": "PLATFORM_ADMIN",
            "targetTenantIds": [0],
            "tenantMode": "EXISTING",
            "reservationBinding": None,
            "agencyBinding": None,
            "protectedProfileId": "platform-v1",
            "validUntil": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 300)
            ),
            "creatorClient": ACTORS["ACCOUNT_CREATE"][0],
            "creatorSubject": SUBJECTS["ACCOUNT_CREATE"],
            "setupClient": ACTORS["SETUP"][0],
            "setupSubject": SUBJECTS["SETUP"],
        }

    def endpoint(self, approval, suffix=""):
        return (
            "/realms/"
            + REALM
            + "/oriso-protected-invitations/v1/approvals/"
            + approval
            + suffix
        )

    def test_real_bound_human_approves_immutable_scope_without_creating_account(self):
        approval, request = str(uuid.uuid4()), {"scope": self.scope()}
        token = self.human()
        before = self.admin("GET", "/users/count")
        type(self).phase = "real-human-approve-http"
        status, result = call(self.base, "PUT", self.endpoint(approval), request, token)
        after = self.admin("GET", "/users/count")
        type(self).approval_observation = {
            "expectedStatus": 201,
            "actualStatus": status,
            "usersBefore": before,
            "usersAfter": after,
            "noAccountCreated": before == after,
            "configurationChecked": type(self).configuration_checked,
        }
        require_active("after-approve-http")
        self.assertEqual(before, after)
        self.assertEqual(201, status)
        self.assertEqual("AUTHORIZED", result["state"])
        self.assertEqual(before, self.admin("GET", "/users/count"))
        self.assertNotIn("accountId", result)
        status, retry = call(self.base, "PUT", self.endpoint(approval), request, token)
        self.assertEqual(200, status)
        self.assertEqual(result["approvalReceipt"], retry["approvalReceipt"])
        request["scope"]["recipient"] = "changed@fixture.invalid"
        self.assertEqual(
            409, call(self.base, "PUT", self.endpoint(approval), request, token)[0]
        )


if __name__ == "__main__":
    unittest.main()
