"""Actual claimed inactivity assertions, configured automation, and native original-enabled restore."""
import copy
import time
import uuid

from lifecycle_fixture import REALM, call, mac
from maintenance_human_fixture import HumanMaintenanceFixture
from ordinary_admin_operations import committed


def exercise(test, helper, primary, peer, observed):
    records = observed['inactivity'] = {}
    original_account, original_creation = helper.account_id, helper.creation_input
    ordinary, creation = committed(test, helper)
    disabled, _ = committed(test, helper)
    disabled_native = helper.admin('GET', '/users/' + disabled); disabled_native['enabled'] = False
    helper.admin('PUT', '/users/' + disabled, disabled_native)
    targets = [('ordinary-disabled', disabled, None), ('ordinary', ordinary, None), ('tenant-admin', type(helper).adopted_account, None),
               ('platform-admin', type(helper).new_platform_account, None), ('manual-platform', peer[0], primary)]
    for label, account, human in targets:
        native = helper.admin('GET', '/users/' + account)
        helper.account_id = account
        helper.creation_input = {'account': {'username': native['username']}}
        work = str(uuid.uuid4()); now = int(time.time())
        origin = {'kind': 'INACTIVITY', 'workflowId': work, 'humanSubject': None,
                  'humanIssuer': None, 'humanClient': None, 'humanAuthority': None}
        if human:
            origin.update(kind='HUMAN_ADMIN', humanSubject=helper.human_subject,
                humanIssuer=type(helper).native_issuer, humanClient='protected-human-web',
                humanAuthority='PROTECTED_ACCOUNT_OPERATIONS_V1')
        target = {'accountId': account, 'tenantId': native['attributes']['tenantId'][0], 'origin': origin}
        workflow = {'v': 1, 'kind': 'INACTIVITY', 'workId': work, 'action': 'SUSPEND',
                    'rowDigest': mac('claimed-inactivity-row/v1', {'synthetic': work}),
                    'revision': 0, 'assignedMonths': 24, 'lastActivity': now - 100,
                    'dueAt': now - 1, 'suspensionOperationId': None}
        read = {'target': target, 'workflow': workflow}
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', read, human, 200)
        records[label] = {'readStatus': status, 'revisionZero': True, 'originalEnabled': native['enabled']}
        with test.subTest(operation='inactivity.' + label + '.read'):
            test.assertEqual(200, status); test.assertEqual(account, current['id'])
        if status != 200:
            continue
        body = {**copy.deepcopy(read), 'operationId': str(uuid.uuid4()),
                'expectedState': current['state'], 'change': {}}
        if human is None:
            future = copy.deepcopy(body); future['operationId'] = str(uuid.uuid4())
            future['workflow']['dueAt'] = now + 10000
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'deactivate', future, None, 403)[0])
        status, suspended = HumanMaintenanceFixture.invoke(helper, 'deactivate', body, human, 200)
        records[label]['suspendStatus'] = status
        with test.subTest(operation='inactivity.' + label + '.suspend'):
            test.assertEqual(200, status); test.assertEqual('UPDATED', suspended['result'])
            test.assertFalse(helper.admin('GET', '/users/' + account)['enabled'])
            test.assertEqual([], helper.admin('GET', '/users/' + account + '/sessions'))
            test.assertEqual((status, suspended), HumanMaintenanceFixture.invoke(helper, 'deactivate', body, human, 200))
        if status != 200:
            continue
        restore_read = copy.deepcopy(read); restore_read['workflow'].update(action='RESTORE', suspensionOperationId=body['operationId'], workId=str(uuid.uuid4()), rowDigest=mac('claimed-inactivity-row/v1', {'restoreOf': work}))
        restore_read['target']['origin']['workflowId'] = restore_read['workflow']['workId']
        status, after = HumanMaintenanceFixture.invoke(helper, 'read', restore_read, human, 200)
        with test.subTest(operation='inactivity.' + label + '.restore-read'):
            test.assertEqual(200, status); test.assertFalse(after['enabled'])
        if status != 200:
            continue
        restore = {**restore_read, 'operationId': str(uuid.uuid4()), 'expectedState': after['state'],
                   'change': {'restoreEnabled': native['enabled']}}
        wrong = copy.deepcopy(restore); wrong['operationId'] = str(uuid.uuid4()); wrong['change']['restoreEnabled'] = not native['enabled']
        test.assertEqual(409, HumanMaintenanceFixture.invoke(helper, 'reactivate', wrong, human, 409)[0])
        status, restored = HumanMaintenanceFixture.invoke(helper, 'reactivate', restore, human, 200)
        records[label]['restoreStatus'] = status
        with test.subTest(operation='inactivity.' + label + '.restore'):
            test.assertEqual(200, status); test.assertEqual('UPDATED', restored['result'])
            test.assertEqual(native['enabled'], helper.admin('GET', '/users/' + account)['enabled'])
            test.assertEqual((status, restored), HumanMaintenanceFixture.invoke(helper, 'reactivate', restore, human, 200))
            records[label]['nativeOriginalEnabledAndExactRetryVerified'] = True
    helper.account_id, helper.creation_input = original_account, original_creation
