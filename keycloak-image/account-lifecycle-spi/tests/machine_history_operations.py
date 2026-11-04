"""Saved machine effects keep current workflow grants and native provenance; no fresh effects."""
import base64
import copy
import hashlib
import hmac
import json
import uuid

from lifecycle_fixture import ACTORS, SUBJECTS, CONTEXT_KEY, canonical, mac
from maintenance_human_fixture import HumanMaintenanceFixture
from profile_transition_operations import human_target


def terminal(test, helper, command, body):
    frozen = copy.deepcopy(body); frozen['operationId'] = str(uuid.uuid4()); frozen['expectedState'] = '0' * 64
    status, result = HumanMaintenanceFixture.invoke(helper, command, frozen, None, 409)
    test.assertEqual(409, status); test.assertEqual({'operationId', 'accountId', 'result', 'status', 'receipt'}, set(result))
    test.assertEqual('NO_EFFECT', result['result']); test.assertEqual(409, result['status'])
    encoded, signature = result['receipt'].split('.')
    test.assertEqual(hmac.new(CONTEXT_KEY, ('maintenance-no-effect-receipt/v1\n' + encoded).encode(), hashlib.sha256).hexdigest(), signature)
    expected = {'realmId': helper.realm_id, 'accountId': frozen['target']['accountId'], 'operationId': frozen['operationId'],
        'command': command, 'ownerClient': ACTORS['ACCOUNT_ADMIN'][0], 'ownerSubject': SUBJECTS['ACCOUNT_ADMIN'],
        'intentDigest': mac('maintenance-intent', frozen), 'previousState': frozen['expectedState'],
        'tenantId': frozen['target']['tenantId'], 'originDigest': mac('maintenance-origin', frozen['target']['origin']), 'result': 'NO_EFFECT', 'status': 409}
    raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    test.assertEqual(expected, json.loads(raw)); test.assertEqual(canonical(expected), raw)
    return frozen, result


def profile_drift(test, helper, command, body, result, no_effect, records, label):
    account = body['target']['accountId']; before = helper.admin('GET', '/users/' + account)
    credentials = helper.admin('GET', '/users/' + account + '/credentials')
    role = helper.admin('GET', '/roles/user')
    test.assertFalse(helper.admin('GET', '/users/' + account + '/role-mappings/realm'))
    test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, command, body, None, 200))
    helper.admin('POST', '/users/' + account + '/role-mappings/realm', [role])
    try:
        read = {'target': body['target'], 'workflow': body['workflow']}
        test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', read, None, 403)[0])
        records[label] = {}
        for outcome, frozen, expected_result in [('UPDATED', body, result), ('NO_EFFECT', no_effect[0], no_effect[1])]:
            status, rejected = HumanMaintenanceFixture.invoke(helper, command, frozen, None, 403)
            records[label][outcome] = status
            with test.subTest(operation='machine-history.' + label + '.profile.' + outcome):
                test.assertEqual(403, status); test.assertNotIn('receipt', rejected)
        test.assertEqual(before, helper.admin('GET', '/users/' + account))
        test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
    finally:
        helper.admin('DELETE', '/users/' + account + '/role-mappings/realm', [role])
    test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, command, body, None, 200))
    test.assertEqual((409, no_effect[1]), HumanMaintenanceFixture.invoke(helper, command, no_effect[0], None, 409))


def read_only_profile(test, helper, command, body, result, no_effect, records, label):
    primary = helper.human(record=False); native = helper.admin('GET', '/users/' + body['target']['accountId'])
    target = human_target(helper, body['target']['accountId'], native)
    def change(operation, patch):
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 200)
        test.assertEqual(200, status)
        frozen = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': patch}
        status, updated = HumanMaintenanceFixture.invoke(helper, operation, frozen, primary, 200)
        test.assertEqual(200, status); test.assertEqual('UPDATED', updated['result'])
    if command == 'deactivate':
        change('ordinary-profile', {'group': '/human-roles/consultant-basic'})
        change('profile-transition', {'transition': 'ADD_AGENCY_ADMIN_IDENTITY', 'group': '/human-roles/consultant-agency-admin-basic'})
    else:
        change('ordinary-profile', {'group': '/human-roles/consultant-agency-admin-basic'})
    read = {'target': body['target'], 'workflow': body['workflow']}
    status, current = HumanMaintenanceFixture.invoke(helper, 'read', read, None, 200)
    test.assertEqual(200, status)
    test.assertEqual({'consultant', 'restricted-agency-admin', 'user-admin'}, set(current['effectiveRoles']))
    before = helper.admin('GET', '/users/' + helper.account_id); credentials = helper.admin('GET', '/users/' + helper.account_id + '/credentials')
    status, rejected = HumanMaintenanceFixture.invoke(helper, command, body, None, 403)
    records[label + '.read-only'] = {'currentReadStatus': 200, 'savedUpdatedStatus': status}
    with test.subTest(operation='machine-history.' + label + '.current-original-mutation-grant'):
        test.assertEqual(403, status); test.assertNotIn('receipt', rejected)
    test.assertEqual((409, no_effect[1]), HumanMaintenanceFixture.invoke(helper, command, no_effect[0], None, 409))
    test.assertEqual(before, helper.admin('GET', '/users/' + helper.account_id)); test.assertEqual(credentials, helper.admin('GET', '/users/' + helper.account_id + '/credentials'))
    records[label + '.read-only']['sameSignedNoEffectReadableWithoutMutationGrant'] = True
    if command != 'deactivate':
        change('ordinary-profile', {'group': '/human-roles/consultant-agency-admin'})
        test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, command, body, None, 200))


def incarnation(test, helper, commands, records, label):
    account = helper.account_id; old = helper.admin('GET', '/users/' + account)
    group = helper.admin('GET', '/users/' + account + '/groups')[0]['id']
    helper.admin('DELETE', '/users/' + account)
    helper.admin('POST', '/partialImport', {'ifResourceExists': 'FAIL', 'users': [{'id': account,
        'username': old['username'], 'enabled': old['enabled'], 'email': old['email'], 'firstName': 'Replacement',
        'lastName': 'Incarnation', 'attributes': {'tenantId': old['attributes']['tenantId']}}]})
    defaults = helper.admin('GET', '/users/' + account + '/role-mappings/realm')
    if defaults: helper.admin('DELETE', '/users/' + account + '/role-mappings/realm', defaults)
    helper.admin('PUT', '/users/' + account + '/groups/' + group)
    fresh = helper.admin('GET', '/users/' + account); test.assertNotEqual(old['createdTimestamp'], fresh['createdTimestamp'])
    credentials = helper.admin('GET', '/users/' + account + '/credentials')
    records[label + '.incarnation'] = {}
    for outcome, command, frozen in commands:
        status, rejected = HumanMaintenanceFixture.invoke(helper, command, frozen, None, 403)
        records[label + '.incarnation'][outcome] = status
        with test.subTest(operation='machine-history.' + label + '.incarnation.' + outcome):
            test.assertEqual(403, status); test.assertNotIn('receipt', rejected)
    test.assertEqual(fresh, helper.admin('GET', '/users/' + account)); test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
