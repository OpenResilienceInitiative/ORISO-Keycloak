"""Approved PLATFORM native tenant reassignment keeps the same protected profile and MAC lineage."""
import copy
import uuid

from maintenance_human_fixture import HumanMaintenanceFixture


def exercise(test, helper, primary, peer, observed):
    records = observed['tenantReassignment'] = {}
    original_account, original_creation = helper.account_id, helper.creation_input
    for label, account in [('adopted', type(helper).adopted_account), ('committed', peer[0])]:
        native = helper.admin('GET', '/users/' + account)
        helper.account_id = account; helper.creation_input = {'account': {'username': native['username']}}
        target = {'accountId': account, 'tenantId': native['attributes']['tenantId'][0], 'origin': {
            'kind': 'HUMAN_ADMIN', 'workflowId': str(uuid.uuid4()), 'humanSubject': helper.human_subject,
            'humanIssuer': type(helper).native_issuer, 'humanClient': 'protected-human-web',
            'humanAuthority': 'PROTECTED_ACCOUNT_OPERATIONS_V1'}}
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 200)
        test.assertEqual(200, status)
        body = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                'change': {'tenantId': '22'}}
        # The current consumed peer is never a PLATFORM reassignment source.
        denied = copy.deepcopy(body); denied['operationId'] = str(uuid.uuid4()); denied['target']['origin']['humanSubject'] = peer[0]
        test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'reassign-tenant', denied, peer[1], 403)[0])
        before_groups = helper.admin('GET', '/users/' + account + '/groups')
        before_roles = helper.admin('GET', '/users/' + account + '/role-mappings')
        status, result = HumanMaintenanceFixture.invoke(helper, 'reassign-tenant', body, primary, 200)
        records[label] = {'status': status, 'preconditions': True}
        with test.subTest(operation='tenant-reassignment.' + label):
            test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
            test.assertEqual(['22'], helper.admin('GET', '/users/' + account)['attributes']['tenantId'])
            test.assertEqual(before_groups, helper.admin('GET', '/users/' + account + '/groups'))
            test.assertEqual(before_roles, helper.admin('GET', '/users/' + account + '/role-mappings'))
            test.assertEqual((status, result), HumanMaintenanceFixture.invoke(helper, 'reassign-tenant', body, primary, 200))
            updated = copy.deepcopy(target); updated['tenantId'] = '22'
            test.assertEqual(200, HumanMaintenanceFixture.invoke(helper, 'read', {'target': updated}, primary, 200)[0])
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 403)[0])
            changed = copy.deepcopy(body); changed['change']['tenantId'] = '23'
            conflict_status, conflict = HumanMaintenanceFixture.invoke(helper, 'reassign-tenant', changed, primary, 409)
            test.assertEqual(409, conflict_status); test.assertNotIn('receipt', conflict)
            records[label]['effectLineageAndExactRetryVerified'] = True
    helper.account_id, helper.creation_input = original_account, original_creation
