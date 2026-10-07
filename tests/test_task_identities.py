"""Fresh-import security contract; reconciliation is separately exercised over HTTP."""

import json
from pathlib import Path
import unittest

REALM = json.loads((Path(__file__).resolve().parents[1] / "realm.json").read_text())


class TaskIdentities(unittest.TestCase):
    def test_fresh_import_has_no_legacy_machine_privileges(self):
        clients = {c["clientId"]: c for c in REALM["clients"]}
        for client in ("backend-admin", "backend-technical"):
            self.assertFalse(clients[client]["enabled"], client)
        self.assertFalse(clients["user-service"]["serviceAccountsEnabled"])
        for user in REALM["users"]:
            if user["username"] in ("technical", "svc-keycloak-admin") or user.get("serviceAccountClientId") in (
                "backend-admin",
                "backend-technical",
            ):
                self.assertFalse(user["enabled"], user["username"])
                self.assertFalse(user.get("realmRoles"), user["username"])
                self.assertFalse(user.get("clientRoles"), user["username"])

    def test_realm_protocol_events_do_not_attach_automatic_machine_scopes(self):
        self.assertEqual(REALM["defaultDefaultClientScopes"], ["basic"])
        self.assertEqual(REALM["defaultOptionalClientScopes"], [])
        app = next(c for c in REALM["clients"] if c["clientId"] == "app")
        self.assertIn("roles", app["defaultClientScopes"])
        self.assertIn("profile", app["defaultClientScopes"])
        self.assertIn("email", app["defaultClientScopes"])

    def test_task_accounts_cannot_inherit_stock_admin_or_generic_technical(self):
        legacy = {"backend-admin", "backend-technical"}
        clients = [c for c in REALM["clients"] if c["clientId"].startswith("backend-") and c["clientId"] not in legacy]
        self.assertEqual(len(clients), 14)
        for client in clients:
            self.assertFalse(client["fullScopeAllowed"])
            self.assertEqual(client["defaultClientScopes"], ["basic"])
            self.assertFalse(client["optionalClientScopes"])
            self.assertFalse(client["directAccessGrantsEnabled"])
            self.assertFalse(client["standardFlowEnabled"])
            user = next(u for u in REALM["users"] if u.get("serviceAccountClientId") == client["clientId"])
            self.assertFalse(user.get("clientRoles"))
            self.assertFalse(set(user["realmRoles"]) & {"technical", "tenant-admin", "realm-admin"})
            self.assertFalse(user.get("groups"))
            self.assertTrue(
                any(m["protocolMapper"] == "oidc-usermodel-realm-role-mapper" for m in client["protocolMappers"])
            )
