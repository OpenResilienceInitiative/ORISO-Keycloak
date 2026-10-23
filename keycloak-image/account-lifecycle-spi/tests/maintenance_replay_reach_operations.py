"""Native journal reach integrity; this fixture edits only its own isolated synthetic row."""
import base64
import copy
import json
from urllib.request import Request, urlopen

from lifecycle_fixture import REALM, SUBJECTS, mac
from maintenance_human_fixture import HumanMaintenanceFixture


def exercise(test, helper, primary, histories, observed):
    body, original = histories['email']
    foreign_body, _ = histories['profile']
    account = helper.account_id
    results = observed['savedHumanReplayReach'] = {}

    def fixture(mode, restore=None):
        headers = {'Authorization': 'Bearer ' + helper.installer,
            'X-ORISO-Replay-Reach-Fixture': body['operationId'],
            'X-ORISO-Replay-Reach-Fixture-Mode': mode}
        if restore is not None:
            headers['X-ORISO-Replay-Reach-Fixture-Restore'] = restore
        if mode == 'FOREIGN_ROW':
            headers['X-ORISO-Replay-Reach-Fixture-Foreign'] = foreign_body['operationId']
        request = Request(helper.base + '/admin/realms/' + REALM + '/users/' + account, headers=headers)
        with urlopen(request, timeout=30) as reply:
            test.assertEqual(200, reply.status)
            test.assertEqual(mode, reply.headers.get('X-ORISO-Replay-Reach-Fixture-Applied'))
            return reply.headers.get('X-ORISO-Replay-Reach-Fixture-Value')

    encoded = fixture('OBSERVE')
    test.assertIsNotNone(encoded)
    envelope = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
    test.assertEqual({'v', 'reach', 'mac'}, set(envelope)); test.assertEqual(1, envelope['v'])
    test.assertEqual([{'family': 'ORDINARY', 'profileId': 'consultant-v1', 'profileVersion': 1,
        'tenantId': '11', 'operations': ['account.email']}], envelope['reach'])
    value = {'v': 1, 'realmId': helper.realm_id, 'operationId': body['operationId'], 'accountId': account,
        'ownerClient': 'backend-account-admin', 'ownerSubject': SUBJECTS['ACCOUNT_ADMIN'], 'command': 'email',
        'intentDigest': mac('maintenance-intent', body), 'expectedState': body['expectedState'],
        'originDigest': mac('maintenance-origin', body['target']['origin']), 'reach': envelope['reach']}
    test.assertEqual(mac('maintenance-replay-reach/v1', value), envelope['mac'])
    before = helper.admin('GET', '/users/' + account)
    groups = helper.admin('GET', '/users/' + account + '/groups')
    credentials = helper.admin('GET', '/users/' + account + '/credentials')
    for mode in ['BAD_MAC', 'EXTRA', 'FOREIGN_ROW', 'MISSING']:
        fixture(mode)
        try:
            status, rejected = HumanMaintenanceFixture.invoke(helper, 'email', body, primary, 403)
            with test.subTest(operation='saved-human-replay-reach.' + mode):
                test.assertEqual(403, status); test.assertNotIn('receipt', rejected)
                test.assertEqual(before, helper.admin('GET', '/users/' + account))
                test.assertEqual(groups, helper.admin('GET', '/users/' + account + '/groups'))
                test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
                results[mode] = {'status': status, 'noReceiptOrEffect': True}
        finally:
            fixture('RESTORE', encoded)
        test.assertEqual((200, original), HumanMaintenanceFixture.invoke(helper, 'email', body, primary, 200))
    drift = copy.deepcopy(before); drift['attributes']['tenantId'] = ['17']
    helper.admin('PUT', '/users/' + account, drift)
    try:
        status, rejected = HumanMaintenanceFixture.invoke(helper, 'email', body, primary, 403)
        with test.subTest(operation='saved-human-replay-reach.current-native-tenant-drift'):
            test.assertEqual(403, status); test.assertNotIn('receipt', rejected)
            test.assertEqual(drift, helper.admin('GET', '/users/' + account))
            results['currentTenantDrift'] = {'status': status, 'noReceiptOrEffect': True}
    finally:
        helper.admin('PUT', '/users/' + account, before)
    test.assertEqual((200, original), HumanMaintenanceFixture.invoke(helper, 'email', body, primary, 200))
    results['originalRowBodyMacAndExactHistoricalResultVerified'] = True


def deleted_history(test, helper, primary, histories, observed):
    """A genuine owned tombstone permits history; a fresh reused UUID never supplies old provenance."""
    import uuid
    body, result = histories['email']
    account = helper.account_id
    test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, 'email', body, primary, 200))
    replacement = {'id': account, 'username': 'replacement-' + uuid.uuid4().hex, 'enabled': True,
        'email': 'replacement-' + uuid.uuid4().hex + '@oriso.org', 'firstName': 'Fresh', 'lastName': 'Incarnation',
        'attributes': {'tenantId': ['77']}}
    helper.admin('POST', '/partialImport', {'ifResourceExists': 'FAIL', 'users': [replacement]})
    fresh = helper.admin('GET', '/users/' + account)
    test.assertEqual(replacement['username'], fresh['username']); test.assertEqual(['77'], fresh['attributes']['tenantId'])
    groups = helper.admin('GET', '/users/' + account + '/groups')
    roles = helper.admin('GET', '/users/' + account + '/role-mappings')
    test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, 'email', body, primary, 200))
    test.assertEqual(fresh, helper.admin('GET', '/users/' + account))
    test.assertEqual(groups, helper.admin('GET', '/users/' + account + '/groups'))
    test.assertEqual(roles, helper.admin('GET', '/users/' + account + '/role-mappings'))
    test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': body['target']}, primary, 403)[0])
    observed['savedHumanReplayReach']['ownedTombstoneHistoryNeverUsesRecreatedNativeUuid'] = True
