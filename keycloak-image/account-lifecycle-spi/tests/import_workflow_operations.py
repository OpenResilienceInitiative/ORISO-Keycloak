"""Existing captured Consultant import assertions; explicit workflow grants stay separate from humans."""
import copy
import hashlib
import uuid

from lifecycle_fixture import mac
from maintenance_human_fixture import HumanMaintenanceFixture
from ordinary_admin_operations import committed
from profile_transition_operations import human_target


def exercise(test, helper, primary, peer, observed):
    records = observed['existingImportWorkflow'] = {}
    original_account, original_creation = helper.account_id, helper.creation_input
    try:
        for family in ['ORDINARY', 'PROTECTED']:
            for source in ['HUMAN_ADMIN', 'IMPORT']:
                account, creation = committed(test, helper) if family == 'ORDINARY' else (peer[0], None)
                native = helper.admin('GET', '/users/' + account)
                helper.account_id = account; helper.creation_input = creation or {'account': {'username': native['username']}}
                target = human_target(helper, account, native); work = str(uuid.uuid4())
                target['origin']['workflowId'] = work
                if source == 'IMPORT':
                    target['origin'].update(kind='IMPORT', humanSubject=None, humanIssuer=None, humanClient=None, humanAuthority=None)
                human = primary if source == 'HUMAN_ADMIN' else None
                workflow = {'v': 1, 'kind': 'IMPORT', 'workId': work,
                    'sourceDigest': hashlib.sha256(b'original captured nonsecret import fixture').hexdigest(),
                    'recordNumber': 1, 'rowDigest': mac('existing-consultant-import-row/v1', {'synthetic': work}),
                    'requiredRoles': ['consultant', 'group-chat-consultant', 'restricted-agency-admin', 'user-admin']}
                read = {'target': target, 'workflow': workflow}
                status, current = HumanMaintenanceFixture.invoke(helper, 'read', read, human, 200)
                label = family + '.' + source
                records[label] = {'readStatus': status, 'preconditions': True, 'explicitSourceAndInstalledProfile': True}
                with test.subTest(operation='import.' + label + '.read'):
                    test.assertEqual(200, status); test.assertEqual(account, current['id'])
                if status != 200:
                    continue
                body = {**copy.deepcopy(read), 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                    'change': {'group': '/human-roles/consultant-agency-admin'}}
                before = helper.admin('GET', '/users/' + account)
                if family == 'PROTECTED':
                    denied, _ = HumanMaintenanceFixture.invoke(helper, 'ordinary-profile', body, human, 403)
                    test.assertEqual(403, denied); test.assertEqual(before, helper.admin('GET', '/users/' + account))
                    records[label]['protectedReadNeverConferredOrdinaryWrite'] = True
                    continue
                wrong = copy.deepcopy(body); wrong['operationId'] = str(uuid.uuid4()); wrong['change']['group'] = '/human-roles/consultant-basic'
                test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'ordinary-profile', wrong, human, 403)[0])
                test.assertEqual(before, helper.admin('GET', '/users/' + account))
                status, result = HumanMaintenanceFixture.invoke(helper, 'ordinary-profile', body, human, 200)
                records[label]['mutationStatus'] = status
                with test.subTest(operation='import.' + label + '.role-union'):
                    test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
                    test.assertEqual((status, result), HumanMaintenanceFixture.invoke(helper, 'ordinary-profile', body, human, 200))
                    after_status, after = HumanMaintenanceFixture.invoke(helper, 'read', read, human, 200)
                    test.assertEqual(200, after_status)
                    test.assertEqual(set(current['effectiveRoles']) | set(workflow['requiredRoles']), set(after['effectiveRoles']))
                    test.assertEqual(target['tenantId'], after['tenantId'])
                    changed = copy.deepcopy(body); changed['workflow']['sourceDigest'] = 'a' * 64
                    conflict_status, conflict = HumanMaintenanceFixture.invoke(helper, 'ordinary-profile', changed, human, 409)
                    test.assertEqual(409, conflict_status); test.assertNotIn('receipt', conflict)
                    records[label]['exactCompleteRoleUnionEffectAndRetryVerified'] = True
    finally:
        helper.account_id, helper.creation_input = original_account, original_creation
