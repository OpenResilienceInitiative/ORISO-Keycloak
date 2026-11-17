"""ORISO-UserService#1666: the read-only statistics role exists and grants nothing else."""
import json
import subprocess
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StatisticsReaderRole(unittest.TestCase):
    def setUp(self):
        self.realm = json.loads((ROOT / 'realm.json').read_text())
        self.roles = {r['name']: r for r in self.realm['roles']['realm']}

    def test_role_is_a_plain_realm_role(self):
        role = self.roles['statistics-reader']
        self.assertFalse(role['composite'], 'must not pull in any other role')
        self.assertFalse(role['clientRole'])
        self.assertEqual('online-beratung', role['containerId'])

    def test_role_is_never_granted_by_default(self):
        default = self.roles[self.realm['defaultRole']['name']]
        self.assertNotIn('statistics-reader', default.get('composites', {}).get('realm', []))
        for name, role in self.roles.items():
            with self.subTest(role=name):
                self.assertNotIn('statistics-reader', role.get('composites', {}).get('realm', []))

    def test_no_user_or_group_carries_the_role_in_the_import(self):
        for user in self.realm.get('users', []):
            self.assertNotIn('statistics-reader', user.get('realmRoles', []))
        for group in self.realm.get('groups', []):
            self.assertNotIn('statistics-reader', group.get('realmRoles', []))

    def test_apply_script_is_valid_bash(self):
        script = ROOT / 'scripts' / 'keycloak-apply-statistics-reader-role.sh'
        subprocess.run(['bash', '-n', str(script)], check=True)
        self.assertIn('statistics-reader', script.read_text())

    def test_apply_script_never_takes_a_password_or_fixed_temp_file(self):
        text = (ROOT / 'scripts' / 'keycloak-apply-statistics-reader-role.sh').read_text()
        code = [l for l in text.splitlines() if not l.lstrip().startswith('#')]
        self.assertFalse(any('--password' in l for l in code))
        self.assertNotIn('/tmp/', text)
        self.assertIn('mktemp', text)


if __name__ == '__main__':
    unittest.main()
