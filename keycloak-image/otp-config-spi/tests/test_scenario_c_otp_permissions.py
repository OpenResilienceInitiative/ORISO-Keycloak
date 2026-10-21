#!/usr/bin/env python3
"""Public native HTTP contract for default-off and C OTP authorization.

All credentials, bearer tokens, OTP seeds and messages stay synthetic/in-memory.
"""

import base64
import json
from pathlib import Path
import sys
import unittest
import uuid
from urllib.parse import urlencode

# Support both direct CLI execution and the isolated CI module loader.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scenario_c_otp_fixture import (
    CLIENT,
    REALM,
    ROLES,
    SECRET,
    SUBJECT,
    ScenarioCOtpFixture,
    call,
)


class ScenarioCOtpPermissions(ScenarioCOtpFixture, unittest.TestCase):
    def test_prior_native_power_over_consultant_is_not_scoped_otp_authority(self):
        self.denied_prior_native_powers("ordinary-consultant", self.ordinary)

    def test_prior_native_power_over_centre_admin_is_not_scoped_otp_authority(self):
        self.denied_prior_native_powers("ordinary-centre-admin", self.centre)

    def test_protected_target_all_five_routes_have_no_credential_or_mail_effect(self):
        self.denied_routes(self.token(), "protected-platform", self.protected)

    def test_unclassified_or_missing_target_is_denied_on_all_routes(self):
        self.denied_routes(self.token(), "unclassified-human", self.unclassified)
        self.denied_routes(self.token(), "missing-human")

    def test_protected_role_drift_is_denied_even_with_actual_native_manage(self):
        drift = self.user("protected-role-drift", ["/human-roles/consultant"])
        role = self.admin("GET", "/roles/single-tenant-admin")
        self.admin("POST", "/users/" + drift + "/role-mappings/realm", [role])
        token = self.token()
        self.assertEqual(204, self.native_manage(token, drift))
        self.denied_routes(token, "protected-role-drift", drift)

    def test_service_account_target_is_denied_even_if_misclassified_ordinary(self):
        self.admin(
            "POST",
            "/clients",
            {
                "clientId": "other-service",
                "enabled": True,
                "serviceAccountsEnabled": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "publicClient": False,
            },
        )
        cid = self.admin("GET", "/clients?clientId=other-service")[0]["id"]
        account = self.admin("GET", "/clients/" + cid + "/service-account-user")
        self.admin(
            "PUT",
            "/users/"
            + account["id"]
            + "/groups/"
            + self.group_id("/human-roles/consultant"),
        )
        token = self.token()
        self.assertEqual(204, self.native_manage(token, account["id"]))
        self.denied_routes(token, account["username"], account["id"])

    def test_view_only_native_members_permission_cannot_read_setup_secrets(self):
        permissions = self.admin("GET", "/clients?clientId=admin-permissions")[0]["id"]
        base = "/clients/" + permissions + "/authz/resource-server"
        permission = self.admin("GET", base + "/permission?name=ordinary-otp-targets")[
            0
        ]
        permission["scopes"] = ["view-members"]
        self.admin("PUT", base + "/permission/scope/" + permission["id"], permission)
        token = self.token()
        self.assertEqual(
            200,
            call(
                self.base,
                "GET",
                "/admin/realms/" + REALM + "/users/" + self.ordinary,
                token=token,
            )[0],
        )
        self.assertEqual(403, self.native_manage(token, self.ordinary))
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_missing_or_wrong_receiver_audience_is_denied_on_all_routes(self):
        client = self.admin("GET", "/clients/" + self.client_id)
        client["protocolMappers"] = [
            m for m in client["protocolMappers"] if m["name"] != "audience-oriso-otp"
        ]
        self.admin("PUT", "/clients/" + self.client_id, client)
        self.denied_routes(
            self.token(validate=False), "ordinary-consultant", self.ordinary
        )

    def test_extra_token_audience_is_denied_on_all_routes(self):
        client = self.admin("GET", "/clients/" + self.client_id)
        mapper = {
            "name": "wrong-audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.custom.audience": "realm-management",
                "access.token.claim": "true",
            },
        }
        client["protocolMappers"].append(mapper)
        self.admin("PUT", "/clients/" + self.client_id, client)
        token = self.token(validate=False)
        payload = token.split(".")[1]
        claims = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        self.assertIn(
            "realm-management",
            claims["aud"],
            "fixture must actually issue the extra recipient",
        )
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_old_token_cannot_hide_current_actor_extra_role(self):
        token = self.token()
        role = self.admin("GET", "/roles/consultant")
        self.admin("POST", "/users/" + SUBJECT + "/role-mappings/realm", [role])
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_old_token_cannot_hide_current_native_role(self):
        token = self.token()
        cid = self.admin("GET", "/clients?clientId=realm-management")[0]["id"]
        role = self.admin("GET", "/clients/" + cid + "/roles/manage-users")
        self.admin(
            "POST", "/users/" + SUBJECT + "/role-mappings/clients/" + cid, [role]
        )
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_actor_interactive_grant_drift_is_denied_on_all_routes(self):
        token = self.token()
        self.admin("PUT", "/clients/" + self.client_id, {"standardFlowEnabled": True})
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_actor_membership_drift_is_denied_on_all_routes(self):
        token = self.token()
        self.admin(
            "PUT",
            "/users/" + SUBJECT + "/groups/" + self.group_id("/human-roles/consultant"),
        )
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_scoped_native_client_permission_rejects_actor(self):
        self.admin("POST", "/clients", {"clientId": "scoped-client", "enabled": True})
        target = self.admin("GET", "/clients?clientId=scoped-client")[0]["id"]
        self.extra_permission("Clients", target, ["manage"])
        token = self.token()
        self.assertEqual(
            204,
            call(
                self.base,
                "PUT",
                "/admin/realms/" + REALM + "/clients/" + target,
                {"name": "Native permitted"},
                token,
            )[0],
        )
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_scoped_native_role_permission_rejects_actor_after_users_component_removed(
        self,
    ):
        role = self.admin("GET", "/roles/consultant")
        user_permission = self.extra_permission(
            "Users", self.unclassified, ["map-roles"]
        )
        self.extra_permission("Roles", role["id"], ["map-role"])
        token = self.token()
        self.assertEqual(
            204,
            call(
                self.base,
                "POST",
                "/admin/realms/"
                + REALM
                + "/users/"
                + self.unclassified
                + "/role-mappings/realm",
                [role],
                token,
            )[0],
        )
        self.admin("DELETE", user_permission)
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_scoped_nonordinary_group_permission_rejects_actor(self):
        self.admin("POST", "/groups", {"name": "unrelated-group"})
        group = self.admin("GET", "/groups?search=unrelated-group")[0]["id"]
        self.extra_permission("Groups", group, ["view"])
        token = self.token()
        self.assertEqual(
            200,
            call(
                self.base,
                "GET",
                "/admin/realms/" + REALM + "/groups/" + group,
                token=token,
            )[0],
        )
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_legacy_client_with_canonical_roles_and_audiences_is_denied_in_c(self):
        self.other_client("backend-admin")
        token = self.token(validate=False, client="backend-admin")
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_direct_human_token_is_not_silently_enabled_in_c(self):
        client = self.admin("GET", "/clients/" + self.client_id)
        client.pop("id")
        client["clientId"] = "fixture-human-login"
        client["serviceAccountsEnabled"] = False
        client["directAccessGrantsEnabled"] = True
        client["fullScopeAllowed"] = True
        for mapper in client["protocolMappers"]:
            mapper.pop("id", None)
        self.admin("POST", "/clients", client)
        roles = [self.admin("GET", "/roles/" + r) for r in ROLES]
        self.admin("POST", "/users/" + self.ordinary + "/role-mappings/realm", roles)
        self.admin(
            "PUT",
            "/users/" + self.ordinary,
            {
                "firstName": "Synthetic",
                "lastName": "Human",
                "email": "fixture-human@oriso.org",
                "emailVerified": True,
            },
        )
        self.admin(
            "PUT",
            "/users/" + self.ordinary + "/reset-password",
            {
                "type": "password",
                "value": "synthetic-human-password-0001",
                "temporary": False,
            },
        )
        status, result = call(
            self.base,
            "POST",
            "/realms/" + REALM + "/protocol/openid-connect/token",
            {
                "grant_type": "password",
                "client_id": "fixture-human-login",
                "client_secret": SECRET,
                "username": "ordinary-consultant",
                "password": "synthetic-human-password-0001",
            },
            form=True,
        )
        self.assertEqual(200, status)
        self.denied_routes(result["access_token"], "ordinary-consultant", self.ordinary)

    def test_missing_current_canonical_role_invalidates_old_token(self):
        token = self.token()
        role = self.admin("GET", "/roles/account-read")
        self.admin("DELETE", "/users/" + SUBJECT + "/role-mappings/realm", [role])
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_composite_mapping_cannot_expand_canonical_actor(self):
        token = self.token()
        role = self.admin("GET", "/roles/account-maintenance")
        added = self.admin("GET", "/roles/consultant")
        self.admin("POST", "/roles/" + role["name"] + "/composites", [added])
        self.denied_routes(token, "ordinary-consultant", self.ordinary)

    def test_foreign_signed_issuer_and_invalid_signature_cannot_reach_any_target(self):
        client = self.admin("GET", "/clients/" + self.client_id)
        client.pop("id")
        client["fullScopeAllowed"] = True
        for mapper in client["protocolMappers"]:
            mapper.pop("id", None)
        foreign = "foreign-otp-fixture"
        status, _ = call(
            self.base,
            "POST",
            "/admin/realms",
            {
                "realm": foreign,
                "enabled": True,
                "clients": [client],
                "roles": {"realm": [{"name": r} for r in ROLES]},
                "users": [
                    {
                        "id": str(uuid.uuid4()),
                        "username": "service-account-" + CLIENT,
                        "enabled": True,
                        "serviceAccountClientId": CLIENT,
                        "realmRoles": ROLES,
                    }
                ],
            },
            self.installer,
        )
        self.assertEqual(201, status)
        self.addCleanup(
            call, self.base, "DELETE", "/admin/realms/" + foreign, token=self.installer
        )
        status, result = call(
            self.base,
            "POST",
            "/realms/" + foreign + "/protocol/openid-connect/token",
            {
                "grant_type": "client_credentials",
                "client_id": CLIENT,
                "client_secret": SECRET,
            },
            form=True,
        )
        self.assertEqual(200, status)
        valid = self.token()
        parts = valid.split(".")
        parts[2] = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        for token in (result["access_token"], ".".join(parts)):
            before = self.credentials(self.ordinary)
            sent = len(self.mail.messages)
            for method, route, body in [
                ("GET", "fetch-otp-setup-info", None),
                ("PUT", "setup-otp", {}),
                ("DELETE", "delete-otp", None),
                ("PUT", "send-verification-mail", {}),
                ("POST", "setup-otp-mail", {}),
            ]:
                self.assertEqual(
                    401,
                    self.otp(token, method, route, "ordinary-consultant", body)[0],
                    route,
                )
            self.assertEqual(before, self.credentials(self.ordinary))
            self.assertEqual(sent, len(self.mail.messages))

    def test_hidden_scoped_native_users_grant_rejects_actor_even_for_ordinary_target(
        self,
    ):
        self.add_users_permission()
        token = self.token()
        self.assertEqual(
            204,
            call(
                self.base,
                "PUT",
                "/admin/realms/" + REALM + "/users/" + self.unclassified,
                {"firstName": "Hidden native grant"},
                token,
            )[0],
        )
        self.assertEqual(
            403,
            self.otp(token, "GET", "fetch-otp-setup-info", "ordinary-consultant")[0],
        )

    def test_native_ordinary_permission_does_not_authorize_protected_otp_target(self):
        token = self.token()
        # Prove the fixture's real native permission before recording an OTP RED.
        self.assertEqual(
            204,
            call(
                self.base,
                "PUT",
                "/admin/realms/" + REALM + "/users/" + self.ordinary,
                {"firstName": "Permitted"},
                token,
            )[0],
        )
        self.assertEqual(
            403,
            call(
                self.base,
                "GET",
                "/admin/realms/" + REALM + "/users/" + self.protected,
                token=token,
            )[0],
        )
        self.assertEqual(
            200,
            self.otp(token, "GET", "fetch-otp-setup-info", "ordinary-consultant")[0],
        )
        self.assertEqual(
            403, self.otp(token, "GET", "fetch-otp-setup-info", "protected-platform")[0]
        )


class LegacyOtpPermissions(ScenarioCOtpFixture, unittest.TestCase):
    MODEL = None

    def token(self):
        return super().token(validate=False, client="backend-admin")

    def test_default_off_preserves_existing_backend_protected_human_all_five_routes(
        self,
    ):
        cid, subject = self.other_client("backend-admin")
        management = self.admin("GET", "/clients?clientId=realm-management")[0]["id"]
        role = self.admin("GET", "/clients/" + management + "/roles/manage-users")
        self.admin(
            "POST", "/users/" + subject + "/role-mappings/clients/" + management, [role]
        )
        self.admin(
            "POST", "/clients/" + cid + "/scope-mappings/clients/" + management, [role]
        )
        client = self.admin("GET", "/clients/" + cid)
        client["protocolMappers"].append(
            {
                "name": "legacy-native-client-roles",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-client-role-mapper",
                "config": {
                    "usermodel.clientRoleMapping.clientId": "realm-management",
                    "claim.name": "resource_access.realm-management.roles",
                    "access.token.claim": "true",
                    "multivalued": "true",
                    "jsonType.label": "String",
                },
            }
        )
        self.admin("PUT", "/clients/" + cid, client)
        self.positive_protocol("protected-platform", self.protected)


if __name__ == "__main__":
    unittest.main()
