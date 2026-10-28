"""Execute the shipped shell entry points against a stateful, strict kcadm boundary."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
FLOW = 'direct-grant-2fa'
PASSWORD_FLOW = 'oriso-ordinary-password'
MAGIC = ['oriso-claimed-magic-link', 'oriso-magic-link-ordinary-password', 'oriso-claimed-magic-link-attach']


def fixture():
    realm = json.loads((ROOT / 'realm.json').read_text())
    state = {'realm': {k: realm[k] for k in ['directGrantFlow', 'browserFlow', 'emailTheme']},
             'flows': {}, 'configs': {}, 'writes': [], 'next': 0, 'providers': MAGIC}
    for config in realm['authenticatorConfig']:
        state['configs'][config['id']] = config
    config_ids = {c['alias']: c['id'] for c in realm['authenticatorConfig']}
    for flow in realm['authenticationFlows']:
        rows = []
        for i, execution in enumerate(flow['authenticationExecutions']):
            row = {'id': flow['alias'] + '-exec-' + str(i), 'requirement': execution['requirement'],
                   'priority': execution['priority'], 'authenticationFlow': execution['authenticatorFlow']}
            if row['authenticationFlow']:
                row['displayName'] = execution['flowAlias']
            else:
                row['providerId'] = execution['authenticator']
            if execution.get('authenticatorConfig'):
                row['authenticationConfig'] = config_ids[execution['authenticatorConfig']]
            rows.append(row)
        state['flows'][flow['alias']] = {'id': flow['alias'], 'rows': rows}
    # Existing browser contract is separate from the direct-grant regression.
    alias = 'browser-email-otp-conditional'
    state['flows'][alias] = {'id': alias, 'rows': [
        {'id': alias + str(i), 'providerId': provider, 'requirement': 'REQUIRED',
         'priority': i * 10, 'authenticationFlow': False}
        for i, provider in enumerate(['conditional-user-configured', 'email-form-authenticator'])]}
    state['flows']['forms']['rows'].append({'id': 'browser-email-parent', 'displayName': alias,
        'authenticationFlow': True, 'requirement': 'CONDITIONAL', 'priority': 30})
    return state


def rows(state, alias, level=0):
    result = []
    for row in sorted(state['flows'][alias]['rows'], key=lambda r: r['priority']):
        result.append({**row, 'level': level})
        if row['authenticationFlow']:
            result.extend(rows(state, row['displayName'], level + 1))
    return result


def fake_kcadm():
    path = Path(os.environ['OPERATOR_FLOW_STATE'])
    state = json.loads(path.read_text())
    verb, route, *args = sys.argv[2:]
    settings = dict(a.split('=', 1) for i, a in enumerate(args) if i and args[i - 1] == '-s')
    value = None
    if verb == 'get' and route.startswith('realms/'):
        value = state['realm']
    elif verb == 'get' and route == 'authentication/authenticator-providers':
        value = [{'id': p} for p in state['providers']]
    elif verb == 'get' and route == 'authentication/flows':
        value = [{'id': f['id'], 'alias': a} for a, f in state['flows'].items()]
    elif verb == 'get' and route.startswith('authentication/flows/') and route.endswith('/executions'):
        alias = route[len('authentication/flows/'):-len('/executions')]
        if alias not in state['flows']: sys.exit(1)
        value = rows(state, alias)
    elif verb == 'get' and route.startswith('authentication/config/'):
        key = route.split('/')[-1]
        if key not in state['configs']: sys.exit(1)
        value = state['configs'][key]
    elif verb == 'get' and route == 'roles/otp-config-admin':
        value = {'name': 'otp-config-admin'}
    elif verb == 'get' and route == 'users':
        print(''); return
    elif verb == 'update' and route.startswith('realms/'):
        state['realm'].update(settings)
    elif verb == 'create' and route == 'authentication/flows':
        alias = settings['alias']
        if alias in state['flows']: sys.exit(1)
        state['flows'][alias] = {'id': alias, 'rows': []}
    elif verb == 'create' and '/executions/' in route and route.startswith('authentication/flows/'):
        alias, kind = route[len('authentication/flows/'):].split('/executions/')
        state['next'] += 1
        row = {'id': 'new-' + str(state['next']), 'requirement': 'DISABLED',
               'priority': max([r['priority'] for r in state['flows'][alias]['rows']] + [0]) + 10,
               'authenticationFlow': kind == 'flow'}
        if kind == 'flow':
            child = settings['alias']
            if child in state['flows']: sys.exit(1)
            state['flows'][child] = {'id': child, 'rows': []}; row['displayName'] = child
        elif kind == 'execution': row['providerId'] = settings['provider']
        else: raise AssertionError('Unexpected create route')
        state['flows'][alias]['rows'].append(row)
    elif verb == 'update' and route.startswith('authentication/flows/') and route.endswith('/executions'):
        incoming = json.loads(Path(args[args.index('-f') + 1]).read_text())
        matches = [r for f in state['flows'].values() for r in f['rows'] if r['id'] == incoming['id']]
        assert len(matches) == 1
        matches[0].update({k: v for k, v in incoming.items() if k != 'level'})
    elif verb == 'delete' and route.startswith('authentication/flows/'):
        alias = route[len('authentication/flows/'):]
        def remove(a):
            for row in state['flows'][a]['rows']:
                if row['authenticationFlow']: remove(row['displayName'])
                state['configs'].pop(row.get('authenticationConfig'), None)
            del state['flows'][a]
        remove(alias)
    elif verb == 'delete' and route.startswith('authentication/executions/'):
        execution = route.split('/')[-1]
        for flow in state['flows'].values(): flow['rows'] = [r for r in flow['rows'] if r['id'] != execution]
    elif verb == 'update' and route.startswith('authentication/config/'):
        key = route.split('/')[-1]
        if key not in state['configs']: sys.exit(1)
        for k, v in settings.items():
            if k.startswith('config.'): state['configs'][key]['config'][k[7:]] = json.loads(v)
            else: state['configs'][key][k] = v
    elif verb == 'create' and route.startswith('authentication/executions/') and route.endswith('/config'):
        key = route.split('/')[2]; config = {'id': 'config-' + key, 'alias': settings['alias'], 'config': {}}
        for k, v in settings.items():
            if k.startswith('config.'): config['config'][k[7:]] = json.loads(v)
        state['configs'][config['id']] = config
        for flow in state['flows'].values():
            for row in flow['rows']:
                if row['id'] == key: row['authenticationConfig'] = config['id']
    else: raise AssertionError('Unexpected kcadm command: ' + verb + ' ' + route)
    if verb != 'get': state['writes'].append([verb, route, settings])
    drop = (state.get('dropOnce') and verb == 'create'
            and route == 'authentication/flows/' + PASSWORD_FLOW + '/executions/execution'
            and settings.get('provider') == 'direct-grant-validate-username')
    if drop: state['dropOnce'] = False
    path.write_text(json.dumps(state))
    if drop: sys.exit(1)
    if value is not None: print(json.dumps(value))


class OperatorAuthenticationFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='operator-flow-'); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.state = self.root / 'state.json'
        self.state.write_text(json.dumps(fixture()))
        cli = self.root / 'kcadm'
        cli.write_text('#!/bin/bash\nexec ' + repr(sys.executable) + ' ' + repr(str(Path(__file__).resolve())) + ' --fake-kcadm "$@"\n')
        cli.chmod(0o700)
        self.scripts = {}
        for key, source in [('apply', 'scripts/keycloak-apply-2fa-flow.sh'),
                            ('verify', 'keycloak-image/scripts/keycloak-verify-2fa-flow.sh')]:
            # Redirect only the transport executable and temporary files; execute actual shell logic.
            script = (ROOT / source).read_text().replace('KC=/opt/keycloak/bin/kcadm.sh', 'KC=' + str(cli))
            script = script.replace('/tmp/2fa-', str(self.root / '2fa-'))
            p = self.root / (key + '.sh'); p.write_text(script); self.scripts[key] = p

    def run_script(self, name):
        env = {**os.environ, 'OPERATOR_FLOW_STATE': str(self.state), 'PYTHONDONTWRITEBYTECODE': '1'}
        env.pop('KC_ADMIN_USER', None)
        return subprocess.run(['bash', str(self.scripts[name])], env=env, capture_output=True, text=True, timeout=30)

    def read(self): return json.loads(self.state.read_text())

    def contract(self, state):
        return {alias: [(r.get('providerId', r.get('displayName')), r['requirement'], r['priority'])
                        for r in sorted(state['flows'][alias]['rows'], key=lambda r: r['priority'])]
                for alias in [FLOW, PASSWORD_FLOW, 'app-otp-conditional', 'email-otp-conditional']}

    def test_verifier_observation_retains_only_fixed_labels_never_native_output(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('operator_image_proof', ROOT / 'scripts/ci/scenario-c-image-proof.py')
        proof = importlib.util.module_from_spec(spec); spec.loader.exec_module(proof)
        private = 'bearer-private-secret subject-private-uuid password-private-value'
        output = '  DRIFT direct-grant-2fa: ' + private + '\n  DRIFT forms: ' + private
        self.assertEqual({'exit': 1, 'failedChecks': ['browserForms', 'directGrant'], 'unclassifiedFailure': False},
                         proof.operator_verifier_observation(1, output))
        self.assertEqual({'exit': 2, 'failedChecks': [], 'unclassifiedFailure': True},
                         proof.operator_verifier_observation(2, private))
        self.assertEqual({'exit': 0, 'failedChecks': [], 'unclassifiedFailure': False},
                         proof.operator_verifier_observation(0, private))

    def test_current_realm_direct_grant_contract_passes_read_only_verifier(self):
        before = self.read(); result = self.run_script('verify')
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual(before, self.read())

    def test_reapplying_current_flow_preserves_magic_link_and_otp_execution_ids(self):
        original = self.read()
        for _ in range(2):
            result = self.run_script('apply'); self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            current = self.read(); self.assertEqual(self.contract(original), self.contract(current))
            for alias in [FLOW, PASSWORD_FLOW, 'app-otp-conditional', 'email-otp-conditional']:
                self.assertEqual(original['flows'][alias], current['flows'][alias])
            self.assertEqual(original['configs'], current['configs'])
            self.assertFalse(any(v == 'delete' for v, _, _ in current['writes']))
        self.assertEqual(0, self.run_script('verify').returncode)

    def test_legacy_migration_keeps_existing_otp_and_only_removes_old_password_executions(self):
        expected = fixture(); legacy = copy.deepcopy(expected)
        legacy['flows'][FLOW]['rows'] = [
            {'id': 'legacy-' + str(i), 'providerId': p, 'authenticationFlow': False,
             'requirement': 'REQUIRED', 'priority': i * 10}
            for i, p in enumerate(['direct-grant-validate-username', 'direct-grant-validate-password'])
        ] + [r for r in legacy['flows'][FLOW]['rows'] if r.get('displayName') in ['app-otp-conditional', 'email-otp-conditional']]
        del legacy['flows'][PASSWORD_FLOW]; self.state.write_text(json.dumps(legacy))
        result = self.run_script('apply'); self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        current = self.read(); self.assertEqual(self.contract(expected), self.contract(current))
        for alias in ['app-otp-conditional', 'email-otp-conditional']:
            self.assertEqual(legacy['flows'][alias], current['flows'][alias])
        self.assertEqual(legacy['configs'], current['configs'])
        self.assertEqual({'authentication/executions/legacy-0', 'authentication/executions/legacy-1'},
                         {route for verb, route, _ in current['writes'] if verb == 'delete'})
        self.assertEqual(0, self.run_script('verify').returncode)

    def test_missing_magic_link_provider_refuses_before_any_native_write(self):
        state = self.read(); state['providers'].remove(MAGIC[0]); self.state.write_text(json.dumps(state))
        result = self.run_script('apply'); self.assertNotEqual(0, result.returncode)
        self.assertEqual([], self.read()['writes'])

    def test_retry_after_applied_create_loses_reply_keeps_original_execution(self):
        expected = fixture(); partial = copy.deepcopy(expected)
        partial['flows'][PASSWORD_FLOW]['rows'] = [r for r in partial['flows'][PASSWORD_FLOW]['rows']
            if r.get('providerId') != 'direct-grant-validate-username']
        partial['dropOnce'] = True; self.state.write_text(json.dumps(partial))
        self.assertNotEqual(0, self.run_script('apply').returncode)
        created = next(r['id'] for r in self.read()['flows'][PASSWORD_FLOW]['rows']
                       if r.get('providerId') == 'direct-grant-validate-username')
        result = self.run_script('apply'); self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        current = self.read(); self.assertEqual(self.contract(expected), self.contract(current))
        self.assertEqual([created], [r['id'] for r in current['flows'][PASSWORD_FLOW]['rows']
                                    if r.get('providerId') == 'direct-grant-validate-username'])
        self.assertFalse(any(v == 'delete' for v, _, _ in current['writes']))

    def test_extra_execution_refuses_without_deleting_current_authentication_paths(self):
        state = self.read(); original_ids = {r['id'] for r in rows(state, FLOW)}
        state['flows'][FLOW]['rows'].append({'id': 'unexpected', 'providerId': 'unexpected-provider',
            'authenticationFlow': False, 'requirement': 'ALTERNATIVE', 'priority': 60})
        self.state.write_text(json.dumps(state))
        result = self.run_script('apply'); self.assertNotEqual(0, result.returncode)
        current = self.read()
        self.assertTrue(original_ids.issubset({r['id'] for r in rows(current, FLOW)}))
        self.assertFalse(any(v == 'delete' for v, _, _ in current['writes']))

    def test_verifier_rejects_missing_disabled_misordered_and_unconditional_password_paths(self):
        for variant in ['missing-claim', 'disabled-attach', 'order', 'unconditional-password', 'missing-condition']:
            with self.subTest(variant=variant):
                state = fixture(); top = state['flows'][FLOW]['rows']
                if variant == 'missing-claim': top.pop(0)
                if variant == 'disabled-attach': top[-1]['requirement'] = 'DISABLED'
                if variant == 'order': top[0]['priority'] = 100
                if variant == 'unconditional-password': top[1]['requirement'] = 'REQUIRED'
                if variant == 'missing-condition': state['flows'][PASSWORD_FLOW]['rows'].pop(0)
                self.state.write_text(json.dumps(state)); self.assertEqual(1, self.run_script('verify').returncode)
                self.assertEqual([], self.read()['writes'])


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--fake-kcadm': fake_kcadm()
    else: unittest.main()
