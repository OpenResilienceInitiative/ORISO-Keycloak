"""Realm-only USER adoption supports the existing independent owned deletion job."""
import uuid

from test_maintenance import MaintenancePermissions


def exercise(test, helper, observed):
    account = type(helper).ordinary_adopted_account
    target = {'accountId': account, 'tenantId': '11', 'origin': {'kind': 'DELETION',
        'workflowId': str(uuid.uuid4()), 'humanSubject': None, 'humanIssuer': None,
        'humanClient': None, 'humanAuthority': None}}
    status, current = MaintenancePermissions.maintenance(helper, 'read', account, {'target': target})
    observed['ordinaryAdoption'] = {'readStatus': status, 'realmOnlyWithoutLifecycleCreate': True}
    with test.subTest(operation='ordinary-adoption.owned-job.read'):
        test.assertEqual(200, status); test.assertEqual(['user'], current['effectiveRoles'])
    if status != 200: return
    user_group = helper.group_id('/human-roles/user'); other = helper.group_id('/human-roles/consultant')
    helper.admin('DELETE', '/users/' + account + '/groups/' + user_group)
    helper.admin('PUT', '/users/' + account + '/groups/' + other)
    test.assertEqual(403, MaintenancePermissions.maintenance(helper, 'read', account, {'target': target})[0])
    helper.admin('DELETE', '/users/' + account + '/groups/' + other)
    helper.admin('PUT', '/users/' + account + '/groups/' + user_group)
    status, current = MaintenancePermissions.maintenance(helper, 'read', account, {'target': target})
    test.assertEqual(200, status)
    body = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': {}}
    status, result = MaintenancePermissions.maintenance(helper, 'delete', account, body)
    with test.subTest(operation='ordinary-adoption.owned-job.delete'):
        test.assertEqual(200, status); test.assertEqual('DELETED', result['result'])
        test.assertEqual((status, result), MaintenancePermissions.maintenance(helper, 'delete', account, body))
        observed['ordinaryAdoption']['actualDeleteExactRetryAndRoleDriftDenial'] = True


def timestamp_boundaries(test, helper, observed):
    from urllib.request import Request, urlopen
    from lifecycle_fixture import REALM
    results = observed['ordinaryAdoptionTimestamp'] = {}
    for boundary in ['null', 'zero']:
        account = getattr(type(helper), 'ordinary_' + boundary + '_adopted_account')
        if boundary == 'null':
            request = Request(helper.base + '/admin/realms/' + REALM + '/users/' + account,
                headers={'Authorization': 'Bearer ' + helper.installer,
                         'X-ORISO-Adoption-Null-Timestamp-Fixture': account})
            with urlopen(request, timeout=30) as reply:
                test.assertEqual(200, reply.status)
                test.assertEqual(account, reply.headers.get('X-ORISO-Adoption-Null-Timestamp-Fixture-Applied'))
        native = helper.admin('GET', '/users/' + account)
        test.assertEqual(None if boundary == 'null' else 0, native.get('createdTimestamp'))
        test.assertEqual(['/human-roles/user'], [g['path'] for g in helper.admin('GET', '/users/' + account + '/groups')])
        target = {'accountId': account, 'tenantId': '11', 'origin': {'kind': 'DELETION',
            'workflowId': str(uuid.uuid4()), 'humanSubject': None, 'humanIssuer': None, 'humanClient': None, 'humanAuthority': None}}
        status, _ = MaintenancePermissions.maintenance(helper, 'read', account, {'target': target})
        test.assertEqual(403, status)
        results[boundary] = {'accountId': account, 'reason': 'NATIVE_CREATED_TIMESTAMP_' + ('NULL' if boundary == 'null' else 'NON_POSITIVE'), 'actualNativeTimestamp': native.get('createdTimestamp'), 'status': status,
            'configuredUserProfileDeniedWithoutGlobalStartupFailure': True}
