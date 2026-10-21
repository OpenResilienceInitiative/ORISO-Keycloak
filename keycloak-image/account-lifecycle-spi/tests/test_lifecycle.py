#!/usr/bin/env python3
"""Real native receiver state/security assertions; no skipped fallback."""

import unittest
import copy
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode
from lifecycle_fixture import (
    ACTORS,
    SUBJECTS,
    REALM,
    IMAGE,
    CONTEXT_KEY,
    HUMAN_GROUPS,
    call,
    mac,
    canonical,
)
import base64
import hmac
import hashlib
import json
import os
from pathlib import Path
import uuid
from lifecycle_fixture import LifecycleFixture


class LifecyclePermissions(LifecycleFixture, unittest.TestCase):
    def test_disabled_create_then_atomic_first_commit_and_no_enable_replay(self):
        attempt = str(uuid.uuid4())
        create = self.creation()
        status, receipt = self.request("create", attempt, create)
        self.assertEqual(201, status)
        user = self.admin("GET", "/users/" + receipt["accountId"])
        self.assertFalse(user["enabled"])
        groups = self.admin("GET", "/users/" + receipt["accountId"] + "/groups")
        self.assertEqual(["/pending-provisioning"], [g["path"] for g in groups])
        command = self.finish(create, receipt)
        status, committed = self.request("commit", attempt, command)
        self.assertEqual(200, status)
        self.assertEqual("COMMITTED", committed["state"])
        self.assertTrue(self.admin("GET", "/users/" + receipt["accountId"])["enabled"])
        self.admin("PUT", "/users/" + receipt["accountId"], {"enabled": False})
        status, repeated = self.request("commit", attempt, command)
        self.assertEqual(200, status)
        self.assertEqual(committed["terminalReceipt"], repeated["terminalReceipt"])
        self.assertFalse(self.admin("GET", "/users/" + receipt["accountId"])["enabled"])

    def test_recovery_fences_old_commit_and_allows_original_owner_bound_admin_cleanup(
        self,
    ):
        attempt = str(uuid.uuid4())
        create = self.creation()
        status, receipt = self.request("create", attempt, create)
        self.assertEqual(201, status)
        recovery = {
            "identity": create["identity"],
            "expectedGeneration": 0,
            "recoveryId": str(uuid.uuid4()),
        }
        status, claimed = self.request(
            "recover", attempt, recovery, actor="ACCOUNT_ADMIN"
        )
        self.assertEqual(200, status)
        self.assertEqual(1, claimed["execution"]["generation"])
        self.assertEqual(
            409, self.request("commit", attempt, self.finish(create, receipt))[0]
        )
        status, cleaned = self.request(
            "compensate",
            attempt,
            self.finish(create, claimed, cleanup=True),
            actor="ACCOUNT_ADMIN",
        )
        self.assertEqual(200, status)
        self.assertEqual("COMPENSATED", cleaned["state"])
        self.assertEqual(
            [],
            self.admin(
                "GET",
                "/users?username=" + create["account"]["username"] + "&exact=true",
            ),
        )

    def test_committed_retry_returns_stored_receipt_after_installer_removes_groups(
        self,
    ):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, opened = self.request("create", attempt, create)
        self.assertEqual(201, status)
        commit = self.finish(create, opened)
        status, terminal = self.request("commit", attempt, commit)
        self.assertEqual(200, status)
        self.admin("DELETE", "/groups/" + self.group_id("/human-roles/consultant"))
        self.admin("DELETE", "/groups/" + self.group_id("/pending-provisioning"))
        before = self.admin("GET", "/users/" + opened["accountId"])
        status, repeated = self.request("commit", attempt, commit)
        self.assertEqual(200, status)
        self.assertEqual(terminal, repeated)
        self.assertEqual(before, self.admin("GET", "/users/" + opened["accountId"]))

    def test_compensated_retry_never_resolves_groups_or_a_reused_account_id(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, opened = self.request("create", attempt, create)
        self.assertEqual(201, status)
        cleanup = self.finish(create, opened, cleanup=True)
        status, terminal = self.request("compensate", attempt, cleanup)
        self.assertEqual(200, status)
        replacement = {
            "id": opened["accountId"],
            "username": "replacement-" + uuid.uuid4().hex,
            "enabled": True,
        }
        self.admin(
            "POST",
            "/partialImport",
            {"ifResourceExists": "FAIL", "users": [replacement]},
        )
        before = self.admin("GET", "/users/" + opened["accountId"])
        self.assertEqual(replacement["username"], before["username"])
        self.admin("DELETE", "/groups/" + self.group_id("/human-roles/consultant"))
        self.admin("DELETE", "/groups/" + self.group_id("/pending-provisioning"))
        status, repeated = self.request("compensate", attempt, cleanup)
        self.assertEqual(200, status)
        self.assertEqual(terminal, repeated)
        self.assertEqual(before, self.admin("GET", "/users/" + opened["accountId"]))

    def test_absent_recovery_tombstone_rejects_delayed_create(self):
        attempt = str(uuid.uuid4())
        create = self.creation()
        recovery = {
            "identity": create["identity"],
            "expectedGeneration": 0,
            "recoveryId": str(uuid.uuid4()),
        }
        status, receipt = self.request(
            "recover", attempt, recovery, actor="ACCOUNT_ADMIN"
        )
        self.assertEqual(200, status)
        self.assertEqual("ABANDONED", receipt["state"])
        self.assertIsNone(receipt["accountId"])
        self.assertEqual(409, self.request("create", attempt, create)[0])
        self.assertEqual(
            [],
            self.admin(
                "GET",
                "/users?username=" + create["account"]["username"] + "&exact=true",
            ),
        )

    def test_exact_create_retry_does_not_rewrite_profile_or_credentials(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, first = self.request("create", attempt, create)
        self.assertEqual(201, status)
        before = self.admin("GET", "/users/" + first["accountId"] + "/credentials")
        profile = self.admin("GET", "/users/" + first["accountId"])
        status, repeated = self.request("create", attempt, create)
        self.assertEqual(200, status)
        self.assertEqual(first, repeated)
        self.assertEqual(
            before, self.admin("GET", "/users/" + first["accountId"] + "/credentials")
        )
        self.assertEqual(profile, self.admin("GET", "/users/" + first["accountId"]))

    def test_owned_read_is_minimal_and_pending_only(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, result = self.request("create", attempt, create)
        self.assertEqual(201, status)
        request = {
            "identity": create["identity"],
            "execution": result["execution"],
            "accountId": result["accountId"],
            "creationProof": result["creationProof"],
        }
        status, projection = self.request("owned-read", attempt, request)
        self.assertEqual(200, status)
        self.assertEqual(
            {
                "id",
                "username",
                "email",
                "firstName",
                "lastName",
                "tenantId",
                "preferredLanguage",
                "enabled",
                "emailVerified",
                "effectiveRoles",
                "passwordChangeRequired",
            },
            set(projection),
        )
        self.assertEqual([], projection["effectiveRoles"])
        self.assertFalse(projection["enabled"])
        self.assertEqual(
            200, self.request("commit", attempt, self.finish(create, result))[0]
        )
        self.assertEqual(409, self.request("owned-read", attempt, request)[0])

    def test_all_five_actors_are_separated_and_admin_cannot_create_or_commit(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        for actor in ("SETUP", "MAIL", "RUNTIME", "ACCOUNT_ADMIN"):
            bearer = self.token(actor)
            commands = (
                ["create", "owned-read", "commit"]
                if actor == "ACCOUNT_ADMIN"
                else ["create", "owned-read", "recover", "commit", "compensate"]
            )
            for command in commands:
                with self.subTest(actor=actor, command=command):
                    self.assertEqual(
                        403,
                        self.request(
                            command, attempt, create, actor=actor, bearer=bearer
                        )[0],
                    )
        self.assertEqual(
            [],
            self.admin(
                "GET",
                "/users?username=" + create["account"]["username"] + "&exact=true",
            ),
        )

    def test_fresh_signed_context_cannot_change_saved_tenant_workflow_group_or_creation(
        self,
    ):
        attempt, create = str(uuid.uuid4()), self.creation()
        self.assertEqual(201, self.request("create", attempt, create)[0])
        variants = []
        for key, value in [("tenantId", "12"), ("initialGroup", "/human-roles/user")]:
            altered = copy.deepcopy(create)
            altered["identity"]["scope"][key] = value
            if key == "initialGroup":
                altered["identity"]["scope"]["registrationKind"] = "ASKER"
            variants.append(altered)
        altered = copy.deepcopy(create)
        altered["identity"]["scope"]["origin"]["workflowId"] = str(uuid.uuid4())
        variants.append(altered)
        for key in ("password", "username"):
            altered = copy.deepcopy(create)
            altered["account"][key] += "-changed"
            variants.append(altered)
        for key in ("humanIssuer", "humanSubject", "humanAuthority"):
            altered = copy.deepcopy(create)
            altered["identity"]["scope"]["origin"][key] += "-changed"
            variants.append(altered)
        altered = copy.deepcopy(create)
        altered["identity"]["scope"]["origin"]["agencyIds"] = ["28"]
        variants.append(altered)
        for altered in variants:
            for refresh_fingerprint in (False, True):
                with self.subTest(fresh_fingerprint=refresh_fingerprint):
                    request = copy.deepcopy(altered)
                    if refresh_fingerprint:
                        request["identity"]["creationFingerprint"] = mac(
                            "creation-payload",
                            {
                                "scope": request["identity"]["scope"],
                                "account": request["account"],
                            },
                        )
                    self.assertIn(
                        self.request("create", attempt, request)[0], (403, 409)
                    )

    def test_frozen_origin_identifier_bounds_match_the_caller_contract(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        origin = create["identity"]["scope"]["origin"]
        origin["provenance"] = "p" * 512
        origin["humanIssuer"] = "https://fixture-human.invalid/" + "i" * (
            512 - len("https://fixture-human.invalid/")
        )
        origin["humanAuthority"] = "a" * 255
        create["identity"]["creationFingerprint"] = mac(
            "creation-payload",
            {"scope": create["identity"]["scope"], "account": create["account"]},
        )
        self.assertEqual(201, self.request("create", attempt, create)[0])
        for field in ("provenance", "humanIssuer", "humanAuthority"):
            with self.subTest(field=field):
                changed = copy.deepcopy(create)
                changed["account"]["username"] += "-" + field
                changed["account"]["email"] = field + "@origin-bounds.invalid"
                changed["identity"]["scope"]["origin"][field] += "x"
                changed["identity"]["creationFingerprint"] = mac(
                    "creation-payload",
                    {
                        "scope": changed["identity"]["scope"],
                        "account": changed["account"],
                    },
                )
                self.assertEqual(
                    400, self.request("create", str(uuid.uuid4()), changed)[0]
                )

    def test_confirmed_duplicate_create_has_only_the_existing_availability_reason(self):
        for field, code in (
            ("username", "USERNAME_NOT_AVAILABLE"),
            ("email", "EMAIL_NOT_AVAILABLE"),
        ):
            with self.subTest(field=field):
                create, attempt = self.creation(), str(uuid.uuid4())
                foreign = {
                    "username": (
                        create["account"]["username"]
                        if field == "username"
                        else "foreign-" + uuid.uuid4().hex
                    ),
                    "email": (
                        create["account"]["email"]
                        if field == "email"
                        else "foreign-" + uuid.uuid4().hex + "@availability.invalid"
                    ),
                    "enabled": False,
                }
                self.admin("POST", "/users", foreign)
                status, result = self.request("create", attempt, create)
                self.assertEqual(409, status)
                self.assertEqual({"code": code}, result)
                recovery = {
                    "identity": create["identity"],
                    "expectedGeneration": 0,
                    "recoveryId": str(uuid.uuid4()),
                }
                status, recovered = self.request("recover", attempt, recovery)
                self.assertEqual(200, status)
                self.assertEqual("ABANDONED", recovered["state"])

    def test_existing_foreign_pending_username_is_not_adopted(self):
        create, attempt = self.creation(), str(uuid.uuid4())
        self.admin(
            "POST",
            "/users",
            {
                "username": create["account"]["username"],
                "enabled": False,
                "groups": ["/pending-provisioning"],
                "attributes": {"oriso.creation-attempt": [attempt]},
            },
        )
        found = self.admin(
            "GET", "/users?username=" + create["account"]["username"] + "&exact=true"
        )[0]
        user = self.admin("GET", "/users/" + found["id"])
        self.assertEqual(409, self.request("create", attempt, create)[0])
        self.assertEqual(user, self.admin("GET", "/users/" + user["id"]))
        recovery = {
            "identity": create["identity"],
            "expectedGeneration": 0,
            "recoveryId": str(uuid.uuid4()),
        }
        status, result = self.request(
            "recover", attempt, recovery, actor="ACCOUNT_ADMIN"
        )
        self.assertEqual(200, status)
        self.assertIsNone(result["accountId"])
        self.assertEqual(
            200,
            self.request(
                "compensate",
                attempt,
                self.finish(create, result, cleanup=True),
                actor="ACCOUNT_ADMIN",
            )[0],
        )
        self.assertEqual(user, self.admin("GET", "/users/" + user["id"]))

    def test_recovery_retry_takeover_and_terminal_retry_fence_old_executions(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, first = self.request("create", attempt, create)
        self.assertEqual(201, status)
        recovery = {
            "identity": create["identity"],
            "expectedGeneration": 0,
            "recoveryId": str(uuid.uuid4()),
        }
        status, one = self.request("recover", attempt, recovery)
        self.assertEqual(200, status)
        self.assertEqual(one, self.request("recover", attempt, recovery)[1])
        takeover = {
            "identity": create["identity"],
            "expectedGeneration": 1,
            "recoveryId": str(uuid.uuid4()),
        }
        status, two = self.request("recover", attempt, takeover, actor="ACCOUNT_ADMIN")
        self.assertEqual(200, status)
        self.assertEqual(2, two["execution"]["generation"])
        self.assertEqual(409, self.request("recover", attempt, recovery)[0])
        self.assertEqual(
            409,
            self.request("compensate", attempt, self.finish(create, one, cleanup=True))[
                0
            ],
        )
        command = self.finish(create, two, cleanup=True)
        status, terminal = self.request(
            "compensate", attempt, command, actor="ACCOUNT_ADMIN"
        )
        self.assertEqual(200, status)
        self.assertEqual(
            terminal,
            self.request("compensate", attempt, command, actor="ACCOUNT_ADMIN")[1],
        )
        repeated = self.request("recover", attempt, takeover, actor="ACCOUNT_ADMIN")
        self.assertEqual(200, repeated[0])
        self.assertEqual(two["recoveryReceipt"], repeated[1]["recoveryReceipt"])

    def test_installer_pending_profile_credential_action_activation_or_membership_edits_deny_cleanup(
        self,
    ):
        for edit in ("profile", "credential", "action", "activation", "group"):
            with self.subTest(edit=edit):
                attempt, create = str(uuid.uuid4()), self.creation()
                status, result = self.request("create", attempt, create)
                self.assertEqual(201, status)
                user = result["accountId"]
                if edit == "credential":
                    self.admin(
                        "PUT",
                        "/users/" + user + "/reset-password",
                        {
                            "type": "password",
                            "value": "Changed-installer-password-0001",
                            "temporary": False,
                        },
                    )
                elif edit == "group":
                    self.admin(
                        "PUT",
                        "/users/"
                        + user
                        + "/groups/"
                        + self.group_id("/human-roles/consultant"),
                    )
                else:
                    self.admin(
                        "PUT",
                        "/users/" + user,
                        (
                            {"firstName": "Installer changed"}
                            if edit == "profile"
                            else (
                                {"requiredActions": ["UPDATE_PASSWORD"]}
                                if edit == "action"
                                else {"enabled": True}
                            )
                        ),
                    )
                before = self.admin("GET", "/users/" + user)
                self.assertEqual(
                    409,
                    self.request(
                        "compensate", attempt, self.finish(create, result, cleanup=True)
                    )[0],
                )
                self.assertEqual(before, self.admin("GET", "/users/" + user))

    def test_native_bypass_denies_foreign_and_owned_pending_mutation_with_same_actor_bearer(
        self,
    ):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, owned = self.request("create", attempt, create)
        self.assertEqual(201, status)
        self.admin(
            "POST",
            "/users",
            {
                "username": "foreign-pending",
                "enabled": False,
                "groups": ["/pending-provisioning"],
            },
        )
        foreign = self.admin("GET", "/users?username=foreign-pending&exact=true")[0][
            "id"
        ]
        for actor in ("ACCOUNT_CREATE", "ACCOUNT_ADMIN"):
            token = self.token(actor)
            self.assertEqual(
                403,
                call(
                    self.base,
                    "POST",
                    "/admin/realms/" + REALM + "/users",
                    {
                        "username": "bypass-" + actor,
                        "enabled": False,
                        "groups": ["/pending-provisioning"],
                    },
                    token,
                )[0],
            )
            for user in (owned["accountId"], foreign):
                before = self.admin("GET", "/users/" + user)
                for method, suffix, body in [
                    ("PUT", "", {"enabled": True}),
                    ("PUT", "", {"attributes": {"oriso.creation-attempt": ["forged"]}}),
                    ("DELETE", "", None),
                    (
                        "PUT",
                        "/groups/" + self.group_id("/human-roles/consultant"),
                        None,
                    ),
                ]:
                    self.assertEqual(
                        403,
                        call(
                            self.base,
                            method,
                            "/admin/realms/" + REALM + "/users/" + user + suffix,
                            body,
                            token,
                        )[0],
                    )
                self.assertEqual(before, self.admin("GET", "/users/" + user))

    def test_bearer_only_and_wrong_proof_binding_cannot_create(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        token = self.token()
        self.assertEqual(
            403,
            call(
                self.base,
                "PUT",
                "/realms/" + REALM + "/oriso-account-lifecycle/v1/attempts/" + attempt,
                create,
                token,
            )[0],
        )
        for key, value in [
            ("purpose", "OTP"),
            ("operation", "account.commit"),
            ("method", "POST"),
            ("realm", "foreign"),
            ("target", "foreign"),
            ("taskClient", "backend-mail"),
            ("taskSubject", str(uuid.uuid4())),
            ("payloadDigest", "0" * 64),
            ("exp", int(time.time()) - 1),
            ("iat", int(time.time()) + 120),
            ("nonce", "bad"),
        ]:
            with self.subTest(claim=key):
                self.assertEqual(
                    403,
                    self.request(
                        "create",
                        attempt,
                        create,
                        proof_changes={key: value},
                        bearer=token,
                    )[0],
                )
        self.assertEqual(
            [],
            self.admin(
                "GET",
                "/users?username=" + create["account"]["username"] + "&exact=true",
            ),
        )

    def test_actor_current_role_or_interactive_grant_drift_invalidates_old_bearer(self):
        for drift in ("role", "interactive"):
            token = self.token()
            attempt, create = str(uuid.uuid4()), self.creation()
            if drift == "role":
                role = self.admin("GET", "/roles/consultant")
                self.admin(
                    "POST",
                    "/users/" + SUBJECTS["ACCOUNT_CREATE"] + "/role-mappings/realm",
                    [role],
                )
            else:
                self.admin(
                    "PUT",
                    "/clients/" + self.client_ids["ACCOUNT_CREATE"],
                    {"standardFlowEnabled": True},
                )
            self.assertEqual(
                403, self.request("create", attempt, create, bearer=token)[0]
            )
            if drift == "role":
                self.admin(
                    "DELETE",
                    "/users/" + SUBJECTS["ACCOUNT_CREATE"] + "/role-mappings/realm",
                    [role],
                )

    def test_unknown_fields_types_protected_kind_and_group_are_rejected(self):
        create = self.creation()
        for alter in ("enabled", "generation", "protected", "unknown-group"):
            body = copy.deepcopy(create)
            if alter == "enabled":
                body["account"]["enabled"] = True
            elif alter == "generation":
                body["execution"]["generation"] = "0"
            elif alter == "protected":
                body["identity"]["scope"]["registrationKind"] = "TENANT_ADMIN"
            else:
                body["identity"]["scope"]["initialGroup"] = "/human-roles/unreviewed"
            self.assertIn(
                self.request("create", str(uuid.uuid4()), body)[0], (400, 403)
            )

    def test_profile_and_password_validation_roll_back_attempt_and_identity_together(
        self,
    ):
        self.admin("PUT", "", {"passwordPolicy": "length(20)"})
        attempt, create = str(uuid.uuid4()), self.creation()
        create["account"]["password"] = "short"
        create["identity"]["creationFingerprint"] = mac(
            "creation-payload",
            {"scope": create["identity"]["scope"], "account": create["account"]},
        )
        self.assertEqual(400, self.request("create", attempt, create)[0])
        self.assertEqual(
            [],
            self.admin(
                "GET",
                "/users?username=" + create["account"]["username"] + "&exact=true",
            ),
        )
        create["account"]["password"] = "Valid-retry-after-rollback-password"
        create["identity"]["creationFingerprint"] = mac(
            "creation-payload",
            {"scope": create["identity"]["scope"], "account": create["account"]},
        )
        self.assertEqual(201, self.request("create", attempt, create)[0])

    def test_group_mapping_drift_and_protected_target_cannot_be_committed_or_deleted(
        self,
    ):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, result = self.request("create", attempt, create)
        self.assertEqual(201, status)
        role = self.admin("GET", "/roles/tenant-admin")
        self.admin(
            "POST",
            "/groups/"
            + self.group_id("/human-roles/consultant")
            + "/role-mappings/realm",
            [role],
        )
        self.assertIn(
            self.request("commit", attempt, self.finish(create, result))[0], (403, 409)
        )
        self.assertFalse(self.admin("GET", "/users/" + result["accountId"])["enabled"])

    def test_concurrent_commit_and_compensation_have_one_terminal_winner(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, result = self.request("create", attempt, create)
        self.assertEqual(201, status)
        token = self.token()
        with ThreadPoolExecutor(max_workers=2) as workers:
            pending = [
                workers.submit(
                    self.request,
                    command,
                    attempt,
                    self.finish(create, result, cleanup=command == "compensate"),
                    bearer=token,
                )
                for command in ("commit", "compensate")
            ]
            outcomes = [future.result() for future in pending]
        self.assertEqual([200, 409], sorted(status for status, _ in outcomes))
        states = [body["state"] for status, body in outcomes if status == 200]
        self.assertEqual(1, len(states))
        found = self.admin(
            "GET", "/users?username=" + create["account"]["username"] + "&exact=true"
        )
        self.assertEqual(states[0] == "COMMITTED", bool(found))
        if found:
            self.assertTrue(found[0]["enabled"])

    def test_absent_recover_racing_create_never_adopts_or_revives(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        recovery = {
            "identity": create["identity"],
            "expectedGeneration": 0,
            "recoveryId": str(uuid.uuid4()),
        }
        token = self.token()
        with ThreadPoolExecutor(max_workers=2) as workers:
            a = workers.submit(self.request, "create", attempt, create, bearer=token)
            b = workers.submit(self.request, "recover", attempt, recovery, bearer=token)
            created, recovered = a.result(), b.result()
        self.assertIn(created[0], (201, 409))
        self.assertEqual(200, recovered[0])
        self.assertIn(recovered[1]["state"], ("RECOVERY_CLAIMED", "ABANDONED"))
        self.assertEqual(409, self.request("create", attempt, create)[0])

    def test_restart_preserves_abandonment_and_terminal_receipts(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        recovery = {
            "identity": create["identity"],
            "expectedGeneration": 0,
            "recoveryId": str(uuid.uuid4()),
        }
        status, before = self.request("recover", attempt, recovery)
        self.assertEqual(200, status)
        subprocess.run(
            ["docker", "restart", self.name], check=True, capture_output=True
        )
        self.refresh_endpoint("same-container-restart")
        self.ready()
        status, after = self.request("recover", attempt, recovery)
        self.assertEqual(200, status)
        self.assertEqual(before, after)
        self.assertEqual(409, self.request("create", attempt, create)[0])

    def test_exact_reviewed_centre_and_combined_centre_roles_commit_together(self):
        for kind, group, wanted in [
            ("AGENCY_ADMIN", "agency-admin", {"restricted-agency-admin", "user-admin"}),
            (
                "CONSULTANT_AGENCY_ADMIN",
                "consultant-agency-admin",
                {
                    "consultant",
                    "group-chat-consultant",
                    "restricted-agency-admin",
                    "user-admin",
                },
            ),
        ]:
            with self.subTest(kind=kind):
                attempt, create = str(uuid.uuid4()), self.creation(
                    kind=kind, group=group
                )
                status, result = self.request("create", attempt, create)
                self.assertEqual(201, status)
                self.assertEqual(
                    200, self.request("commit", attempt, self.finish(create, result))[0]
                )
                groups = self.admin("GET", "/users/" + result["accountId"] + "/groups")
                self.assertEqual(["/human-roles/" + group], [g["path"] for g in groups])
                roles = self.admin(
                    "GET",
                    "/users/" + result["accountId"] + "/role-mappings/realm/composite",
                )
                self.assertEqual(wanted, {role["name"] for role in roles})

    def test_no_email_asker_and_anonymous_keep_validated_dummy_policy_and_locale(self):
        for kind, origin in [("ASKER", "REGISTRATION"), ("ANONYMOUS", "ANONYMOUS")]:
            with self.subTest(kind=kind):
                attempt, create = str(uuid.uuid4()), self.creation(
                    kind=kind, group="user", origin=origin
                )
                scope = create["identity"]["scope"]
                scope["tenantId"] = None
                scope["origin"].update(
                    {
                        "humanIssuer": None,
                        "humanSubject": None,
                        "humanAuthority": None,
                        "agencyIds": [],
                    }
                )
                create["account"].update(
                    {
                        "email": None,
                        "firstName": None,
                        "lastName": None,
                        "preferredLanguage": None,
                        "passwordTemporary": True,
                    }
                )
                create["identity"]["creationFingerprint"] = mac(
                    "creation-payload", {"scope": scope, "account": create["account"]}
                )
                status, result = self.request("create", attempt, create)
                self.assertEqual(201, status)
                user = self.admin("GET", "/users/" + result["accountId"])
                self.assertEqual(
                    result["accountId"] + "@lifecycle-fixture.invalid", user["email"]
                )
                read = {
                    "identity": create["identity"],
                    "execution": result["execution"],
                    "accountId": result["accountId"],
                    "creationProof": result["creationProof"],
                }
                read_status, stored = self.request("owned-read", attempt, read)
                self.assertEqual(200, read_status)
                self.assertEqual("de", stored["preferredLanguage"])
                self.assertIn("UPDATE_PASSWORD", user["requiredActions"])
                self.assertFalse(user["enabled"])

    def test_real_initial_password_is_unusable_pending_and_works_only_after_commit(
        self,
    ):
        self.admin(
            "POST",
            "/clients",
            {
                "clientId": "fixture-user-login",
                "enabled": True,
                "publicClient": True,
                "directAccessGrantsEnabled": True,
                "standardFlowEnabled": False,
                "serviceAccountsEnabled": False,
            },
        )
        attempt, create = str(uuid.uuid4()), self.creation()
        status, result = self.request("create", attempt, create)
        self.assertEqual(201, status)
        form = {
            "client_id": "fixture-user-login",
            "grant_type": "password",
            "username": create["account"]["username"],
            "password": create["account"]["password"],
        }
        path = "/realms/" + REALM + "/protocol/openid-connect/token"
        self.assertEqual(400, call(self.base, "POST", path, form, form=True)[0])
        self.assertEqual(
            200, self.request("commit", attempt, self.finish(create, result))[0]
        )
        status, authenticated = call(self.base, "POST", path, form, form=True)
        self.assertEqual(200, status)
        self.assertTrue(authenticated.get("access_token"))

    def test_current_group_client_role_and_composite_drift_invalidate_old_actor(self):
        token = self.token()
        subject = SUBJECTS["ACCOUNT_CREATE"]
        changes = []
        native = self.admin("GET", "/clients?clientId=realm-management")[0]["id"]
        role = self.admin("GET", "/clients/" + native + "/roles/manage-users")
        changes.append(
            (
                "/users/" + subject + "/role-mappings/clients/" + native,
                "POST",
                "DELETE",
                [role],
            )
        )
        changes.append(
            (
                "/users/"
                + subject
                + "/groups/"
                + self.group_id("/human-roles/consultant"),
                "PUT",
                "DELETE",
                None,
            )
        )
        added = self.admin("GET", "/roles/consultant")
        changes.append(
            ("/roles/account-provisioning/composites", "POST", "DELETE", [added])
        )
        for path, add, remove, body in changes:
            with self.subTest(path=path):
                self.admin(add, path, body)
                self.assertEqual(
                    403,
                    self.request(
                        "create", str(uuid.uuid4()), self.creation(), bearer=token
                    )[0],
                )
                self.admin(remove, path, body)

    def test_hidden_scoped_native_permission_is_measured_then_actor_denied(self):
        self.admin(
            "POST", "/users", {"username": "native-scope-target", "enabled": False}
        )
        target = self.admin("GET", "/users?username=native-scope-target&exact=true")[0][
            "id"
        ]
        cid = self.admin("GET", "/clients?clientId=admin-permissions")[0]["id"]
        base = "/clients/" + cid + "/authz/resource-server"
        self.admin(
            "POST",
            base + "/policy/user",
            {
                "name": "unexpected-lifecycle-native",
                "users": [SUBJECTS["ACCOUNT_CREATE"]],
            },
        )
        self.admin(
            "POST",
            base + "/permission/scope",
            {
                "name": "hidden-native-user",
                "resourceType": "Users",
                "resources": [target],
                "scopes": ["manage", "view"],
                "policies": ["unexpected-lifecycle-native"],
            },
        )
        token = self.token()
        self.assertEqual(
            204,
            call(
                self.base,
                "PUT",
                "/admin/realms/" + REALM + "/users/" + target,
                {"firstName": "Actual native grant"},
                token,
            )[0],
        )
        self.assertEqual(
            403,
            self.request("create", str(uuid.uuid4()), self.creation(), bearer=token)[0],
        )

    def test_wrong_audience_invalid_signature_and_expired_proof_do_not_create(self):
        token = self.token()
        chunks = token.split(".")
        chunks[2] = ("A" if chunks[2][0] != "A" else "B") + chunks[2][1:]
        self.assertEqual(
            401,
            self.request(
                "create", str(uuid.uuid4()), self.creation(), bearer=".".join(chunks)
            )[0],
        )
        for key, value in [
            ("aud", "oriso-otp"),
            ("taskSubject", SUBJECTS["ACCOUNT_ADMIN"]),
            ("iat", "0"),
            ("exp", int(time.time()) + 600),
        ]:
            self.assertEqual(
                403,
                self.request(
                    "create",
                    str(uuid.uuid4()),
                    self.creation(),
                    proof_changes={key: value},
                )[0],
            )
        client = self.admin("GET", "/clients/" + self.client_ids["ACCOUNT_CREATE"])
        client["protocolMappers"].append(
            {
                "name": "unreviewed-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": "realm-management",
                    "access.token.claim": "true",
                },
            }
        )
        self.admin("PUT", "/clients/" + self.client_ids["ACCOUNT_CREATE"], client)
        self.assertEqual(
            403, self.request("create", str(uuid.uuid4()), self.creation())[0]
        )

    def test_foreign_cleanup_identity_and_account_cannot_retarget_admin(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, opened = self.request("create", attempt, create)
        self.assertEqual(201, status)
        recovery = {
            "identity": copy.deepcopy(create["identity"]),
            "expectedGeneration": 0,
            "recoveryId": str(uuid.uuid4()),
        }
        recovery["identity"]["scope"]["origin"]["provenance"] = "foreign-workflow"
        self.assertEqual(
            403, self.request("recover", attempt, recovery, actor="ACCOUNT_ADMIN")[0]
        )
        cleanup = self.finish(create, opened, cleanup=True)
        cleanup["accountId"] = SUBJECTS["ACCOUNT_ADMIN"]
        self.assertEqual(
            403, self.request("compensate", attempt, cleanup, actor="ACCOUNT_ADMIN")[0]
        )
        self.assertFalse(self.admin("GET", "/users/" + opened["accountId"])["enabled"])

    def test_terminal_cleanup_does_not_delete_later_reused_username(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, opened = self.request("create", attempt, create)
        self.assertEqual(201, status)
        cleanup = self.finish(create, opened, cleanup=True)
        status, terminal = self.request("compensate", attempt, cleanup)
        self.assertEqual(200, status)
        self.admin(
            "POST",
            "/users",
            {"username": create["account"]["username"], "enabled": True},
        )
        replacement = self.admin(
            "GET", "/users?username=" + create["account"]["username"] + "&exact=true"
        )[0]["id"]
        repeated = self.request("compensate", attempt, cleanup)
        self.assertEqual(200, repeated[0])
        self.assertEqual(terminal, repeated[1])
        self.assertTrue(self.admin("GET", "/users/" + replacement)["enabled"])

    def test_unexpected_default_grants_roll_back_creation_instead_of_silent_stripping(
        self,
    ):
        default = self.admin("GET")["defaultRole"]["name"]
        role = self.admin("GET", "/roles/consultant")
        self.admin("POST", "/roles/" + default + "/composites", [role])
        create = self.creation()
        self.assertEqual(403, self.request("create", str(uuid.uuid4()), create)[0])
        self.assertEqual(
            [],
            self.admin(
                "GET",
                "/users?username=" + create["account"]["username"] + "&exact=true",
            ),
        )

    def test_malformed_utf8_duplicate_keys_trailing_json_and_oversize_are_400(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        canonical_body = canonical(create)
        invalid = canonical_body.replace(
            b'"firstName":"Synthetic"', b'"firstName":"\xff"'
        )
        self.assertNotEqual(canonical_body, invalid)
        for wire in (
            invalid,
            canonical_body.replace(
                b'"firstName":"Synthetic"',
                b'"firstName":"Synthetic","firstName":"Changed"',
            ),
            canonical_body + b" {}",
            b" " * 65537 + canonical_body,
        ):
            with self.subTest(kind="wire"):
                self.assertEqual(
                    400, self.request("create", attempt, create, wire_body=wire)[0]
                )

    def test_changed_actual_service_subject_cannot_inherit_configured_creator_ownership(
        self,
    ):
        cid = self.client_ids["ACCOUNT_CREATE"]
        self.admin("PUT", "/clients/" + cid, {"serviceAccountsEnabled": False})
        self.admin("PUT", "/clients/" + cid, {"serviceAccountsEnabled": True})
        replacement = self.admin("GET", "/clients/" + cid + "/service-account-user")[
            "id"
        ]
        self.assertNotEqual(SUBJECTS["ACCOUNT_CREATE"], replacement)
        previous = self.admin("GET", "/users/" + replacement + "/role-mappings/realm")
        if previous:
            self.admin(
                "DELETE", "/users/" + replacement + "/role-mappings/realm", previous
            )
        roles = [
            self.admin("GET", "/roles/" + role) for role in ACTORS["ACCOUNT_CREATE"][1]
        ]
        self.admin("POST", "/users/" + replacement + "/role-mappings/realm", roles)
        self.admin(
            "PUT",
            "/users/"
            + replacement
            + "/groups/"
            + self.group_id("/protected-admins/technical-identities"),
        )
        status, issued = call(
            self.base,
            "POST",
            "/realms/" + REALM + "/protocol/openid-connect/token",
            {
                "client_id": ACTORS["ACCOUNT_CREATE"][0],
                "client_secret": "synthetic-lifecycle-ACCOUNT_CREATE",
                "grant_type": "client_credentials",
            },
            form=True,
        )
        self.assertEqual(200, status)
        self.assertEqual(
            403,
            self.request(
                "create",
                str(uuid.uuid4()),
                self.creation(),
                bearer=issued["access_token"],
            )[0],
        )

    def test_foreign_issuer_and_really_expired_bearer_are_unauthenticated(self):
        template = self.admin("GET", "/clients/" + self.client_ids["ACCOUNT_CREATE"])
        template.pop("id", None)
        template["fullScopeAllowed"] = True
        for mapper in template["protocolMappers"]:
            mapper.pop("id", None)
        foreign = "foreign-lifecycle-" + uuid.uuid4().hex[:8]
        status, _ = call(
            self.base,
            "POST",
            "/admin/realms",
            {
                "realm": foreign,
                "enabled": True,
                "clients": [template],
                "roles": {
                    "realm": [{"name": role} for role in ACTORS["ACCOUNT_CREATE"][1]]
                },
                "users": [
                    {
                        "id": str(uuid.uuid4()),
                        "username": "service-account-backend-account-create",
                        "enabled": True,
                        "serviceAccountClientId": "backend-account-create",
                        "realmRoles": ACTORS["ACCOUNT_CREATE"][1],
                    }
                ],
            },
            self.installer,
        )
        self.assertEqual(201, status)
        self.addCleanup(
            lambda: call(
                self.base, "DELETE", "/admin/realms/" + foreign, token=self.installer
            )
        )
        status, issued = call(
            self.base,
            "POST",
            "/realms/" + foreign + "/protocol/openid-connect/token",
            {
                "client_id": "backend-account-create",
                "client_secret": "synthetic-lifecycle-ACCOUNT_CREATE",
                "grant_type": "client_credentials",
            },
            form=True,
        )
        self.assertEqual(200, status)
        self.assertEqual(
            401,
            self.request(
                "create",
                str(uuid.uuid4()),
                self.creation(),
                bearer=issued["access_token"],
            )[0],
        )
        client = self.admin("GET", "/clients/" + self.client_ids["ACCOUNT_CREATE"])
        client.setdefault("attributes", {})["access.token.lifespan"] = "1"
        self.admin("PUT", "/clients/" + self.client_ids["ACCOUNT_CREATE"], client)
        expired = self.token()
        time.sleep(2.1)
        self.assertEqual(
            401,
            self.request("create", str(uuid.uuid4()), self.creation(), bearer=expired)[
                0
            ],
        )

    def test_creation_receipt_is_self_describing_canonical_and_bound_to_saved_identity(
        self,
    ):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, opened = self.request("create", attempt, create)
        self.assertEqual(201, status)
        parts = opened["creationProof"].split(".")
        self.assertEqual(
            2,
            len(parts),
            "Creation receipt must include its immutable verifiable payload",
        )
        payload = json.loads(
            base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
        )
        self.assertEqual(
            {
                "v",
                "realmName",
                "realmId",
                "attemptId",
                "accountId",
                "ownerClient",
                "ownerSubject",
                "scope",
                "initialGroupId",
                "initialRoleFingerprint",
                "creationFingerprint",
            },
            set(payload),
        )
        self.assertEqual(1, payload["v"])
        self.assertEqual(REALM, payload["realmName"])
        self.assertEqual(self.realm_id, payload["realmId"])
        self.assertEqual(attempt, payload["attemptId"])
        self.assertEqual(opened["accountId"], payload["accountId"])
        self.assertEqual("backend-account-create", payload["ownerClient"])
        self.assertEqual(SUBJECTS["ACCOUNT_CREATE"], payload["ownerSubject"])
        self.assertEqual(create["identity"]["scope"], payload["scope"])
        self.assertEqual(
            create["identity"]["creationFingerprint"], payload["creationFingerprint"]
        )
        self.assertEqual(
            self.group_id("/human-roles/consultant"), payload["initialGroupId"]
        )
        self.assertEqual(
            mac("initial-roles", ["consultant", "group-chat-consultant"]),
            payload["initialRoleFingerprint"],
        )
        self.assertEqual(
            base64.urlsafe_b64encode(canonical(payload)).decode().rstrip("="), parts[0]
        )
        signature = (
            base64.urlsafe_b64encode(
                hmac.new(
                    CONTEXT_KEY,
                    ("creation-proof\n" + parts[0]).encode(),
                    hashlib.sha256,
                ).digest()
            )
            .decode()
            .rstrip("=")
        )
        self.assertEqual(signature, parts[1])
        self.assertEqual(
            opened["creationProof"],
            self.request("create", attempt, create)[1]["creationProof"],
        )


class LifecycleOff(LifecycleFixture, unittest.TestCase):
    ENABLED = False

    def test_off_module_has_no_registered_command_or_legacy_fallback(self):
        self.assertEqual(
            404, self.request("create", str(uuid.uuid4()), self.creation())[0]
        )


class InvalidLifecycleConfiguration(unittest.TestCase):
    def test_enabled_malformed_key_fails_startup_and_cleans_only_owned_container(self):
        jar = Path(os.environ.get("LIFECYCLE_C_TEST_JAR", ""))
        self.assertTrue(jar.is_file())
        name = "oriso-c-lifecycle-invalid-" + uuid.uuid4().hex[:10]
        command = [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--memory",
            "1g",
            "--cpus",
            "2",
            "--label",
            "oriso-c-lifecycle-test=true",
            "-e",
            "JAVA_OPTS_APPEND=-Xms128m -Xmx512m -XX:ActiveProcessorCount=2",
            "-e",
            "TASK_IDENTITY_MODEL=FIVE_ACTORS",
            "-e",
            "ORISO_ACCOUNT_LIFECYCLE_ENABLED=true",
            "-e",
            "ORISO_ACCOUNT_LIFECYCLE_REALM=" + REALM,
            "-e",
            "IDENTITY_ACCOUNT_CREATE_SERVICE_SUBJECT=" + SUBJECTS["ACCOUNT_CREATE"],
            "-e",
            "IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT=" + SUBJECTS["ACCOUNT_ADMIN"],
            "-e",
            "ORISO_TASK_CONTEXT_KEY=not-a-base64-key",
            "-e",
            "ORISO_ACCOUNT_LIFECYCLE_GROUPS="
            + json.dumps({"/human-roles/" + k: v for k, v in HUMAN_GROUPS.items()}),
            "-v",
            str(jar.resolve())
            + ":/opt/keycloak/providers/account-lifecycle-spi.jar:ro",
            IMAGE,
            "start-dev",
        ]
        subprocess.run(command, check=True, capture_output=True)
        try:
            deadline = time.monotonic() + 90
            while True:
                state = json.loads(
                    subprocess.check_output(["docker", "inspect", name], text=True)
                )[0]["State"]
                if not state["Running"]:
                    self.assertNotEqual(0, state["ExitCode"])
                    output = subprocess.run(
                        ["docker", "logs", name], capture_output=True, text=True
                    )
                    self.assertTrue(
                        "Lifecycle key must be base64" in output.stdout + output.stderr,
                        "Startup must fail for the deliberately invalid context key",
                    )
                    break
                if time.monotonic() > deadline:
                    self.fail(
                        "Enabled malformed lifecycle configuration did not fail startup"
                    )
                time.sleep(1)
        finally:
            subprocess.run(
                ["docker", "rm", "-f", name], check=True, capture_output=True
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
