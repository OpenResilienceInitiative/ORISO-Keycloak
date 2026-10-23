"""Actual SELF profile/email/locale effects for source-supported local owner families."""
import base64
import copy
import json
import uuid

from lifecycle_fixture import LifecycleFixture, REALM, call
from maintenance_human_fixture import HumanMaintenanceFixture
from profile_transition_operations import committed_kind


def account(test, helper, label, account_id, human, observed, only_locale=False):
    original_account, original_creation = helper.account_id, helper.creation_input
    records = observed.setdefault('actualSelfProfile', {})[label] = {}
    native = helper.admin('GET', '/users/' + account_id)
    helper.account_id = account_id; helper.creation_input = {'account': {'username': native['username']}}
    claims = human.split('.')[1]
    claims = json.loads(base64.urlsafe_b64decode(claims + '=' * (-len(claims) % 4)))
    roles = {r['name'] for r in helper.admin('GET', '/users/' + account_id + '/role-mappings/realm/composite')}
    test.assertEqual(account_id, claims['sub']); test.assertEqual(roles, set(claims['realm_access']['roles']))
    target = {'accountId': account_id, 'tenantId': native['attributes']['tenantId'][0], 'origin': {
        'kind': 'SELF', 'workflowId': str(uuid.uuid4()), 'humanSubject': account_id,
        'humanIssuer': type(helper).native_issuer, 'humanClient': 'protected-human-web',
        'humanAuthority': 'PROTECTED_ACCOUNT_OPERATIONS_V1' if label.startswith('PROTECTED') else None}}
    try:
        for command, change in [('profile', {'firstName': 'ActualSelf', 'lastName': 'NamesOnly', 'email': native['email']}),
            ('email', {'firstName': 'ActualSelf', 'lastName': 'AtomicEmail', 'email': 'self-' + uuid.uuid4().hex + '@oriso.org'}),
            ('email', {'email': 'self-single-' + uuid.uuid4().hex + '@oriso.org'}), ('locale', {'locale': 'en'})]:
            if only_locale and command != 'locale': continue
            name = command + ('.combined' if len(change) == 3 and command == 'email' else '.single')
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 200)
            test.assertEqual(200, status); test.assertEqual(roles, set(current['effectiveRoles']))
            body = {'target': copy.deepcopy(target), 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': change}
            before = helper.admin('GET', '/users/' + account_id)
            credentials = helper.admin('GET', '/users/' + account_id + '/credentials')
            status, result = HumanMaintenanceFixture.invoke(helper, command, body, human, 200)
            record = records[name] = {'status': status, 'actualRawSelfCurrentFullNativeProfileAndProvenance': True}
            with test.subTest(operation='self-profile.' + label + '.' + name):
                test.assertEqual(200, status); test.assertEqual('UPDATED', result.get('result'))
                after = helper.admin('GET', '/users/' + account_id)
                for key, value in change.items():
                    test.assertEqual(value, after['attributes']['locale'][0] if key == 'locale' else after.get(key))
                if command == 'email': test.assertTrue(after['emailVerified'])
                test.assertEqual(before['username'], after['username']); test.assertEqual(before['enabled'], after['enabled'])
                test.assertEqual(before['attributes']['tenantId'], after['attributes']['tenantId'])
                test.assertEqual(credentials, helper.admin('GET', '/users/' + account_id + '/credentials'))
                test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, command, body, human, 200))
                test.assertEqual(after, helper.admin('GET', '/users/' + account_id))
                record['oneAtomicEffectExplicitGrantsAndExactReplayWithoutCredentialOrScopeWrite'] = True
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 200)
        test.assertEqual(200, status)
        before = helper.admin('GET', '/users/' + account_id)
        for change in [{'firstName': 'Unsafe', 'lastName': 'ProfileEmail', 'email': 'ungranted-' + uuid.uuid4().hex + '@oriso.org'},
            {'firstName': 'Unsafe', 'lastName': 'NativeExtra', 'email': before['email'], 'enabled': False}]:
            body = {'target': copy.deepcopy(target), 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': change}
            status, result = HumanMaintenanceFixture.invoke(helper, 'profile', body, human, 403)
            test.assertIn(status, {400, 403}); test.assertNotIn('receipt', result)
            test.assertEqual(before, helper.admin('GET', '/users/' + account_id))
        wrong = copy.deepcopy(target); wrong['origin']['humanSubject'] = str(uuid.uuid4())
        status, result = HumanMaintenanceFixture.invoke(helper, 'read', {'target': wrong}, human, 403)
        test.assertEqual(403, status); test.assertNotIn('receipt', result)
        records['profileCannotChangeEmailOrNativeRepresentationAndForeignSelfDenied'] = True
    finally:
        helper.account_id, helper.creation_input = original_account, original_creation


def exercise(test, helper, tenant, observed):
    for kind, group in [('ASKER', 'user'), ('CONSULTANT', 'consultant'), ('CONSULTANT_AGENCY_ADMIN', 'consultant-agency-admin')]:
        account_id, creation = committed_kind(test, helper, kind, group)
        native = helper.admin('GET', '/users/' + account_id)
        status, token = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
            {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': native['username'],
             'password': creation['account']['password'], 'scope': 'openid'}, form=True)
        test.assertEqual(200, status)
        account(test, helper, 'ORDINARY.' + ('USER' if kind == 'ASKER' else kind), account_id, token['access_token'], observed, only_locale=kind == 'ASKER')
    native = helper.admin('GET', '/users/' + tenant[0])
    password = LifecycleFixture.creation(helper)['account']['password']
    status, token = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
        {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': native['username'],
         'password': password, 'scope': 'openid'}, form=True)
    test.assertEqual(200, status)
    account(test, helper, 'PROTECTED.TENANT_ADMIN_DUAL', tenant[0], token['access_token'], observed)
