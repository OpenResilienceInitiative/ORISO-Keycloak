import json
from pathlib import Path
import unittest


class BackendServiceClients(unittest.TestCase):
    def test_confidential_scoped_service_clients(self):
        realm = json.loads((Path(__file__).resolve().parents[1] / "realm.json").read_text())
        clients = {c["clientId"]: c for c in realm["clients"]}
        users = {u.get("serviceAccountClientId"): u for u in realm["users"]}
        expected = {
            "backend-technical": ("12316d09-a9da-41b9-a13e-ee2c515800b5", [], {}),
            "backend-admin": ("615a7bf8-3e12-40c7-a949-f88640acea8e", [], {}),
        }
        for name, (subject, roles, client_roles) in expected.items():
            with self.subTest(client=name):
                client = clients[name]
                self.assertFalse(client["enabled"])
                self.assertTrue(client["serviceAccountsEnabled"])
                for field in (
                    "publicClient",
                    "directAccessGrantsEnabled",
                    "standardFlowEnabled",
                    "implicitFlowEnabled",
                    "fullScopeAllowed",
                ):
                    self.assertFalse(client[field], field)
                self.assertNotIn("secret", client, "import must generate an unpredictable secret")
                user = users[name]
                self.assertEqual(subject, user["id"])
                self.assertEqual(roles, user["realmRoles"])
                self.assertEqual(client_roles, user.get("clientRoles", {}))
                self.assertFalse(user.get("credentials"), "no password for service account")
                mappings = [m for m in realm["scopeMappings"] if m.get("client") == name]
                self.assertEqual([], mappings)
                cm = realm["clientScopeMappings"].get("realm-management", [])
                self.assertEqual(
                    [{"client": name, "roles": client_roles["realm-management"]}] if client_roles else [],
                    [m for m in cm if m.get("client") == name],
                )
        self.assertTrue(clients["app"]["publicClient"])
        for user in realm["users"]:
            if user["username"] in ("technical", "svc-keycloak-admin"):
                self.assertFalse(user["enabled"])
                self.assertFalse(user.get("credentials"))


if __name__ == "__main__":
    unittest.main()
