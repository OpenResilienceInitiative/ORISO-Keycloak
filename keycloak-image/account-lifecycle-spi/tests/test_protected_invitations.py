#!/usr/bin/env python3
"""Protected receiving HTTP seam. Synthetic fixture; missing setup is an error."""

import base64
import copy
import hashlib
import hmac
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
    CONTEXT_KEY,
    canonical,
    mac,
    call,
)
from protected_resources import HOSTED_PROFILE, require_start, require_active
from protected_creation_cases import ProtectedCreationCases
from protected_terminal_cases import ProtectedTerminalCases
from protected_cleanup_cases import ProtectedCleanupCases
from protected_fence_cases import ProtectedFenceCases
from protected_expiry_cases import ProtectedExpiryCases
from protected_reconciliation_cases import ProtectedReconciliationCases
from protected_approval_replay_cases import ProtectedApprovalReplayCases

HUMAN = None  # Set only from the actual native user lookup, never a proposed UUID.
ISSUER = "http://protected-fixture.invalid/realms/" + REALM
HUMAN_PASSWORD = "synthetic-human-password-0001"


class ProtectedInvitations(
    ProtectedApprovalReplayCases,
    ProtectedCreationCases,
    ProtectedTerminalCases,
    ProtectedCleanupCases,
    ProtectedFenceCases,
    ProtectedExpiryCases,
    ProtectedReconciliationCases,
    LifecycleFixture,
    unittest.TestCase,
):
    @classmethod
    def setUpClass(cls):
        global HUMAN
        cls.preconditions = []
        cls.configuration_checked = False
        cls.approval_observation = None
        cls.native_image_ids = []
        cls.setup_precondition = None
        cls.fixture_diagnostic = None
        cls.authorization_controls = []
        cls.cancel_observation = None
        cls.status_observation = None
        cls.proof_controls = []
        cls.absent_cancel_observation = None
        cls.expiry_observation = None
        cls.create_observation = None
        cls.read_observation = None
        cls.read_proof_controls = []
        cls.commit_observation = None
        cls.recover_observation = None
        cls.recover_proof_controls = []
        cls.absent_recover_observation = None
        cls.compensate_observation = None
        cls.compensate_proof_controls = []
        cls.abandoned_compensate_observation = None
        cls.bound_cancel_observation = None
        cls.expired_commit_observation = None
        cls.creation_reconciliation_observation = None
        cls.duplicate_workflow_observation = None
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
        cls.phase = "configure-native-human-tenant-attribute"
        native_profile = helper.admin("GET", "/users/profile")
        helper.assertFalse(
            any(
                attribute["name"] == "tenantId"
                for attribute in native_profile["attributes"]
            )
        )
        native_profile["attributes"].append(
            {
                "name": "tenantId",
                "multivalued": False,
                "permissions": {"view": ["admin", "user"], "edit": ["admin"]},
                "validations": {
                    "length": {"min": 1, "max": 19},
                    "pattern": {"pattern": "0|[1-9][0-9]{0,18}"},
                },
            }
        )
        helper.admin("PUT", "/users/profile", native_profile)
        cls.phase = "create-native-human"
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
        cls.human_subject = HUMAN
        cls.native_issuer = ISSUER
        cls.phase = "persisted-native-human-tenant"
        native_human = helper.admin("GET", "/users/" + HUMAN)
        helper.assertEqual(["0"], native_human.get("attributes", {}).get("tenantId"))
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
        configuration = cls.prepare_installation(helper, configuration)
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
        cls.native_configured_profiles = copy.deepcopy(configuration["profiles"])
        cls.phase = "configured-native-ready"

    @classmethod
    def prepare_installation(cls, helper, configuration):
        """Separate native installation suite supplies one explicit counterfactual."""
        return configuration

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

    def human(self, username="reviewed-human", expected_subject=None, record=True):
        expected_subject = HUMAN if expected_subject is None else expected_subject
        require_active("human-preconditions")
        type(self).phase = "human-preconditions"
        status, value = call(
            self.base,
            "POST",
            "/realms/" + REALM + "/protocol/openid-connect/token",
            {
                "client_id": "protected-human-web",
                "grant_type": "password",
                "username": username,
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
        type(self).phase = "required-native-human-token-fields"
        for required in (
            "sub",
            "iss",
            "azp",
            "tenantId",
            "aud",
            "realm_access",
            "exp",
            "sid",
        ):
            if required not in claims:
                type(self).fixture_diagnostic = {
                    "location": "native-human-access-token",
                    "missingField": required,
                }
                self.fail("Native human token lacks a required field")
        type(self).phase = "native-human-token-policy"
        self.assertEqual(expected_subject, claims["sub"])
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
        type(self).phase = "native-human-client-policy"
        self.assertTrue(client["enabled"])
        self.assertTrue(client["standardFlowEnabled"])
        self.assertFalse(client["serviceAccountsEnabled"])
        self.assertFalse(client["fullScopeAllowed"])
        type(self).phase = "native-human-current-profile"
        native = self.admin("GET", "/users/" + expected_subject)
        self.assertTrue(native["enabled"])
        self.assertIsNone(native.get("serviceAccountClientLink"))
        self.assertEqual(
            {"agency-admin", "tenant-admin"}, set(claims["realm_access"]["roles"])
        )
        type(self).phase = "native-human-effective-grants"
        native_roles = self.admin(
            "GET", "/users/" + expected_subject + "/role-mappings/realm/composite"
        )
        self.assertEqual(
            {"agency-admin", "tenant-admin"}, {role["name"] for role in native_roles}
        )
        self.assertEqual(
            [], self.admin("GET", "/users/" + expected_subject + "/groups")
        )
        mappings = self.admin("GET", "/users/" + expected_subject + "/role-mappings")
        self.assertFalse(mappings.get("clientMappings"))
        self.assertGreater(claims["exp"], time.time())
        type(self).phase = "native-human-userinfo-validation"
        status, current = call(
            self.base,
            "GET",
            "/realms/" + REALM + "/protocol/openid-connect/userinfo",
            token=bearer,
        )
        self.assertEqual(200, status)
        if "sub" not in current:
            type(self).fixture_diagnostic = {
                "location": "native-userinfo",
                "missingField": "sub",
            }
            self.fail("Native UserInfo lacks required subject")
        self.assertEqual(expected_subject, current["sub"])
        type(self).phase = "native-human-current-session"
        self.assertTrue(claims.get("sid"))
        self.assertTrue(
            any(
                session["id"] == claims["sid"]
                for session in self.admin(
                    "GET", "/users/" + expected_subject + "/sessions"
                )
            )
        )
        if not record:
            return bearer
        type(self).preconditions.append(
            {
                "stage": "configured" if type(self).configuration_checked else "seed",
                "realmId": self.realm_id,
                "subject": expected_subject,
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

    def protected_machine_request(
        self,
        operation,
        approval,
        body,
        actor="SETUP",
        *,
        claim_overrides=None,
        proof_domain="protected-invitation-proof/v1",
        payload_domain="protected-invitation-payload/v1",
        proof_body=None,
        attempt=None,
    ):
        bearer = self.token(actor)
        payload = bearer.split(".")[1]
        native = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        self.assertEqual(ISSUER, native["iss"])
        audiences = native["aud"]
        self.assertEqual(
            {
                "SETUP": {
                    "agencyservice",
                    "consultingtypeservice",
                    "tenantservice",
                    "userservice",
                },
                "ACCOUNT_CREATE": {"oriso-account-lifecycle", "userservice"},
                "ACCOUNT_ADMIN": {
                    "oriso-account-lifecycle",
                    "oriso-otp",
                    "userservice",
                },
                "MAIL": {"oriso-account-lifecycle", "userservice"},
                "RUNTIME": {"oriso-account-lifecycle", "userservice"},
            }[actor],
            set([audiences] if isinstance(audiences, str) else audiences),
        )
        method = "PUT" if attempt is not None and operation == "create" else "POST"
        target = "realm/" + self.realm_id + "/protected-invitation/" + approval
        suffix = "/" + operation
        operation_claim = "protected-invitation." + operation
        if attempt is not None:
            self.assertEqual(attempt, str(uuid.UUID(attempt)))
            target += "/account-attempt/" + attempt
            suffix = "/attempts/" + attempt
            if operation != "create":
                suffix += "/" + operation
            operation_claim = "protected-account." + (
                "creation-recover" if operation == "recover" else operation
            )
        now = int(time.time())
        claims = {
            "iss": "userservice",
            "aud": "oriso-protected-invitations",
            "purpose": {
                "SETUP": "INVITE_RESERVATIONS",
                "ACCOUNT_CREATE": "ACCOUNT_PROVISIONING",
                "ACCOUNT_ADMIN": "ACCOUNT_MAINTENANCE",
                "MAIL": "SYSTEM_EMAIL_DELIVERY",
                "RUNTIME": "RUNTIME_POLICY",
            }[actor],
            "operation": operation_claim,
            "method": method,
            "actor": actor,
            "realm": REALM,
            "target": target,
            "taskClient": ACTORS[actor][0],
            "taskSubject": SUBJECTS[actor],
            "payloadDigest": mac(
                payload_domain, body if proof_body is None else proof_body
            ),
            "jti": str(uuid.uuid4()),
            "nonce": uuid.uuid4().hex,
            "iat": now,
            "exp": now + 60,
        }
        claims.update(claim_overrides or {})
        encoded = base64.urlsafe_b64encode(canonical(claims)).decode().rstrip("=")
        signature = (
            base64.urlsafe_b64encode(
                hmac.new(
                    CONTEXT_KEY,
                    (proof_domain + "\n" + encoded).encode(),
                    hashlib.sha256,
                ).digest()
            )
            .decode()
            .rstrip("=")
        )
        return call(
            self.base,
            method,
            self.endpoint(approval, suffix),
            body,
            bearer,
            proof=encoded + "." + signature,
        )

    def test_installer_routine_and_unbound_human_cannot_authorize_protected_scope(self):
        for actor in ACTORS:
            with self.subTest(actor=actor):
                native = self.admin(
                    "GET",
                    "/clients/" + self.client_ids[actor] + "/service-account-user",
                )
                self.assertEqual(SUBJECTS[actor], native["id"])
                roles = self.admin(
                    "GET", "/users/" + native["id"] + "/role-mappings/realm/composite"
                )
                self.assertEqual(set(ACTORS[actor][1]), {r["name"] for r in roles})
                bearer = self.token(actor)
                before = self.admin("GET", "/users/count")
                status, _ = call(
                    self.base,
                    "PUT",
                    self.endpoint(str(uuid.uuid4())),
                    {"scope": self.scope()},
                    bearer,
                )
                self.assertIn(status, (401, 403))
                self.assertEqual(before, self.admin("GET", "/users/count"))
                type(self).authorization_controls.append(
                    {
                        "principal": actor,
                        "status": status,
                        "nativePrincipalMatched": True,
                    }
                )
        status, _ = call(
            self.base,
            "PUT",
            self.endpoint(str(uuid.uuid4())),
            {"scope": self.scope()},
            self.installer,
        )
        self.assertIn(status, (401, 403))
        type(self).authorization_controls.append(
            {"principal": "INSTALLER", "status": status, "nativePrincipalMatched": True}
        )

        username = "unbound-" + uuid.uuid4().hex
        self.admin(
            "POST",
            "/users",
            {
                "username": username,
                "enabled": True,
                "email": username + "@fixture.invalid",
                "emailVerified": True,
                "firstName": "Unbound",
                "lastName": "Human",
                "attributes": {"tenantId": ["0"]},
                "credentials": [
                    {"type": "password", "value": HUMAN_PASSWORD, "temporary": False}
                ],
            },
        )
        users = self.admin("GET", "/users?username=" + username + "&exact=true")
        self.assertEqual(1, len(users))
        subject = users[0]["id"]
        self.assertEqual(subject, str(uuid.UUID(subject)))
        self.addCleanup(lambda: self.admin("DELETE", "/users/" + subject))
        defaults = self.admin("GET", "/users/" + subject + "/role-mappings/realm")
        if defaults:
            self.admin("DELETE", "/users/" + subject + "/role-mappings/realm", defaults)
        roles = [
            self.admin("GET", "/roles/" + r) for r in ("agency-admin", "tenant-admin")
        ]
        self.admin("POST", "/users/" + subject + "/role-mappings/realm", roles)
        bearer = self.human(username, subject, record=False)
        before = self.admin("GET", "/users/count")
        status, _ = call(
            self.base,
            "PUT",
            self.endpoint(str(uuid.uuid4())),
            {"scope": self.scope()},
            bearer,
        )
        self.assertEqual(403, status)
        self.assertEqual(before, self.admin("GET", "/users/count"))
        type(self).authorization_controls.append(
            {
                "principal": "UNBOUND_REAL_HUMAN",
                "status": status,
                "nativePrincipalMatched": True,
            }
        )

    def test_human_cancel_is_durable_idempotent_and_blocks_delayed_approve(self):
        approval, request = str(uuid.uuid4()), {"scope": self.scope()}
        bearer = self.human(record=False)
        before = self.admin("GET", "/users/count")
        status, approved = call(
            self.base, "PUT", self.endpoint(approval), request, bearer
        )
        self.assertEqual(201, status)
        receipt = approved["approvalReceipt"]
        cancel = {
            "cancellationId": str(uuid.uuid4()),
            "scopeDigest": receipt["scopeDigest"],
            "workflowId": request["scope"]["workflowId"],
            "inviteId": request["scope"]["inviteId"],
            "authorizationRevision": 1,
            "reason": "REVOKED",
            "absentScope": None,
            "approvalRequestDigest": receipt["approvalRequestDigest"],
        }
        type(self).phase = "real-human-cancel-http"
        status, cancelled = call(
            self.base, "POST", self.endpoint(approval, "/cancel"), cancel, bearer
        )
        after = self.admin("GET", "/users/count")
        type(self).cancel_observation = {
            "actualStatus": status,
            "expectedStatus": 200,
            "nativeHumanValidated": True,
            "sourceApprovalCreated": True,
            "noAccountCreated": before == after,
        }
        self.assertEqual(before, after)
        self.assertEqual(200, status)
        self.assertEqual("CANCELLED", cancelled["state"])
        self.assertEqual(receipt, cancelled["approvalReceipt"])
        self.assertTrue(cancelled["transitionReceipt"])
        status, retry = call(
            self.base, "POST", self.endpoint(approval, "/cancel"), cancel, bearer
        )
        self.assertEqual(200, status)
        self.assertEqual(cancelled, retry)
        cancel["cancellationId"] = str(uuid.uuid4())
        status, retry = call(
            self.base, "POST", self.endpoint(approval, "/cancel"), cancel, bearer
        )
        self.assertEqual(200, status)
        self.assertEqual(cancelled["transitionReceipt"], retry["transitionReceipt"])
        cancel["scopeDigest"] = "0" * 64
        self.assertEqual(
            409,
            call(self.base, "POST", self.endpoint(approval, "/cancel"), cancel, bearer)[
                0
            ],
        )
        self.assertEqual(
            409, call(self.base, "PUT", self.endpoint(approval), request, bearer)[0]
        )
        self.assertEqual(before, self.admin("GET", "/users/count"))

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

    def test_setup_status_reconciles_lost_approval_reply_without_human_bearer(self):
        approval, request = str(uuid.uuid4()), {"scope": self.scope()}
        request_digest = mac(
            "protected-approval-request/v1",
            {
                "request": request,
                "issuerRealm": self.realm_id,
                "issuerSubject": HUMAN,
            },
        )
        bearer = self.human(record=False)
        before = self.admin("GET", "/users/count")
        status, reference = call(
            self.base, "PUT", self.endpoint(approval), request, bearer
        )
        self.assertEqual(201, status)
        del bearer  # Reconciliation dispatch has no human bearer or approval reply input.
        query = {
            "scopeDigest": None,
            "workflowId": request["scope"]["workflowId"],
            "inviteId": request["scope"]["inviteId"],
            "authorizationRevision": 1,
            "attemptId": None,
            "approvalRequestDigest": request_digest,
        }
        type(self).phase = "setup-lost-reply-status-http"
        status, reconciled = self.protected_machine_request("status", approval, query)
        after = self.admin("GET", "/users/count")
        type(self).status_observation = {
            "actualStatus": status,
            "expectedStatus": 200,
            "sourceApprovalCreated": True,
            "requestDigestComputedBeforeDispatch": True,
            "humanBearerNotForwarded": True,
            "nativeSetupCanonicalAudiencesMatched": True,
            "noAccountCreated": before == after,
        }
        self.assertEqual(before, after)
        self.assertEqual(200, status)
        self.assertEqual("AUTHORIZED", reconciled["state"])
        self.assertEqual(request_digest, reconciled["approvalRequestDigest"])
        self.assertEqual(reference["approvalReceipt"], reconciled["approvalReceipt"])
        self.assertNotIn(request["scope"]["recipient"], json.dumps(reconciled))
        self.assertNotIn("accountId", reconciled)
        status, retry = self.protected_machine_request("status", approval, query)
        self.assertEqual(200, status)
        self.assertEqual(reconciled, retry)
        query["workflowId"] = str(uuid.uuid4())
        self.assertEqual(
            403, self.protected_machine_request("status", approval, query)[0]
        )

    def test_setup_status_denies_wrong_proof_and_payload_domains_independently(self):
        approval, request = str(uuid.uuid4()), {"scope": self.scope()}
        status, reference = call(
            self.base, "PUT", self.endpoint(approval), request, self.human(record=False)
        )
        self.assertEqual(201, status)
        query = {
            "scopeDigest": reference["scopeDigest"],
            "workflowId": request["scope"]["workflowId"],
            "inviteId": request["scope"]["inviteId"],
            "authorizationRevision": 1,
            "attemptId": None,
            "approvalRequestDigest": reference["approvalRequestDigest"],
        }
        controls = {
            "ordinary-proof-domain": {"proof_domain": "proof"},
            "ordinary-payload-domain": {"payload_domain": "payload"},
            "different-payload-body": {"proof_body": {"execution": {"generation": 0}}},
            "wrong-purpose": {"claim_overrides": {"purpose": "ACCOUNT_PROVISIONING"}},
            "ordinary-proof-audience": {
                "claim_overrides": {"aud": "oriso-account-lifecycle"}
            },
            "foreign-target": {
                "claim_overrides": {
                    "target": "realm/"
                    + self.realm_id
                    + "/protected-invitation/"
                    + str(uuid.uuid4())
                }
            },
            "wrong-method": {"claim_overrides": {"method": "PUT"}},
            "wrong-operation": {
                "claim_overrides": {"operation": "protected-invitation.cancel"}
            },
            "wrong-native-subject": {
                "claim_overrides": {"taskSubject": SUBJECTS["MAIL"]}
            },
            "wrong-native-client": {
                "claim_overrides": {"taskClient": ACTORS["MAIL"][0]}
            },
            "wrong-actor": {"claim_overrides": {"actor": "ACCOUNT_ADMIN"}},
            "expired-proof": {
                "claim_overrides": {
                    "iat": int(time.time()) - 120,
                    "exp": int(time.time()) - 60,
                }
            },
            "mail-native-bearer": {"actor": "MAIL"},
            "runtime-native-bearer": {"actor": "RUNTIME"},
        }
        before = self.admin("GET", "/users/count")
        for name, options in controls.items():
            with self.subTest(control=name):
                status, _ = self.protected_machine_request(
                    "status", approval, query, **options
                )
                type(self).proof_controls.append({"control": name, "status": status})
                self.assertEqual(403, status)
        self.assertEqual(before, self.admin("GET", "/users/count"))
        status, current = self.protected_machine_request("status", approval, query)
        self.assertEqual(200, status)
        self.assertEqual(reference, current)

    def test_setup_absent_cancel_tombstone_blocks_delayed_human_approval(self):
        approval, request = str(uuid.uuid4()), {"scope": self.scope()}
        bearer = self.human(record=False)
        digest = mac(
            "protected-approval-request/v1",
            {
                "request": request,
                "issuerRealm": self.realm_id,
                "issuerSubject": HUMAN,
            },
        )
        absent_scope = dict(
            request["scope"],
            originalIssuerRealm=self.realm_id,
            originalIssuerSubject=HUMAN,
        )
        cancel = {
            "cancellationId": str(uuid.uuid4()),
            "scopeDigest": None,
            "workflowId": request["scope"]["workflowId"],
            "inviteId": request["scope"]["inviteId"],
            "authorizationRevision": 1,
            "reason": "ISSUANCE_ABORTED",
            "absentScope": absent_scope,
            "approvalRequestDigest": digest,
        }
        before = self.admin("GET", "/users/count")
        status, cancelled = self.protected_machine_request("cancel", approval, cancel)
        after = self.admin("GET", "/users/count")
        type(self).absent_cancel_observation = {
            "actualStatus": status,
            "expectedStatus": 200,
            "nativeSetupCanonicalAudiencesMatched": True,
            "originalRequestDigestPredispatch": True,
            "nativeHumanValidatedForOriginalIdentity": True,
            "noPriorApproveDispatched": True,
            "noAccountCreated": before == after,
        }
        self.assertEqual(before, after)
        self.assertEqual(200, status)
        self.assertEqual("CANCELLED", cancelled["state"])
        self.assertIsNone(cancelled["approvalReceipt"])
        self.assertIsNotNone(cancelled["transitionReceipt"])
        self.assertEqual(digest, cancelled["approvalRequestDigest"])
        status, retry = self.protected_machine_request("cancel", approval, cancel)
        self.assertEqual(200, status)
        self.assertEqual(cancelled, retry)
        self.assertEqual(
            409, call(self.base, "PUT", self.endpoint(approval), request, bearer)[0]
        )
        status, _ = self.protected_machine_request(
            "status",
            approval,
            {
                "scopeDigest": None,
                "workflowId": request["scope"]["workflowId"],
                "inviteId": request["scope"]["inviteId"],
                "authorizationRevision": 1,
                "attemptId": None,
                "approvalRequestDigest": digest,
            },
        )
        self.assertEqual(200, status)
        cancel["approvalRequestDigest"] = "0" * 64
        self.assertEqual(
            409, self.protected_machine_request("cancel", approval, cancel)[0]
        )
        self.assertEqual(before, self.admin("GET", "/users/count"))

    def test_expired_authorization_materializes_one_immutable_terminal_receipt(self):
        approval, request = str(uuid.uuid4()), {"scope": self.scope()}
        deadline = int(time.time()) + 6
        request["scope"]["validUntil"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(deadline)
        )
        bearer = self.human(record=False)
        before = self.admin("GET", "/users/count")
        status, approved = call(
            self.base, "PUT", self.endpoint(approval), request, bearer
        )
        self.assertEqual(201, status)
        query = {
            "scopeDigest": approved["scopeDigest"],
            "workflowId": request["scope"]["workflowId"],
            "inviteId": request["scope"]["inviteId"],
            "authorizationRevision": 1,
            "attemptId": None,
            "approvalRequestDigest": approved["approvalRequestDigest"],
        }
        status, current = self.protected_machine_request("status", approval, query)
        self.assertEqual(200, status)
        self.assertEqual("AUTHORIZED", current["state"])
        while time.time() <= deadline + 1:
            require_active("waiting-for-receiver-approval-expiry")
            time.sleep(0.2)
        self.assertEqual(
            409, call(self.base, "PUT", self.endpoint(approval), request, bearer)[0]
        )
        status, expired = self.protected_machine_request("status", approval, query)
        after = self.admin("GET", "/users/count")
        type(self).expiry_observation = {
            "actualStatus": status,
            "actualState": expired.get("state"),
            "expectedState": "EXPIRED",
            "sourceLiveApprovalCreated": True,
            "sourceLiveStatusObserved": True,
            "nativeSetupValidated": True,
            "receiverDeadlineElapsed": time.time() > deadline,
            "noAccountCreated": before == after,
        }
        self.assertEqual(before, after)
        self.assertEqual(200, status)
        self.assertEqual("EXPIRED", expired["state"])
        self.assertEqual(approved["approvalReceipt"], expired["approvalReceipt"])
        self.assertIsNotNone(expired["transitionReceipt"])
        status, retry = self.protected_machine_request("status", approval, query)
        self.assertEqual(200, status)
        self.assertEqual(expired, retry)
        self.assertEqual(
            409, call(self.base, "PUT", self.endpoint(approval), request, bearer)[0]
        )
        request["scope"]["validUntil"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 300)
        )
        self.assertEqual(
            409, call(self.base, "PUT", self.endpoint(approval), request, bearer)[0]
        )
        self.assertEqual(before, self.admin("GET", "/users/count"))


if __name__ == "__main__":
    unittest.main()
