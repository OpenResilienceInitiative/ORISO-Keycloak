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
