"""Approved PLATFORM native tenant reassignment keeps the same protected profile and MAC lineage."""
import copy
import uuid

from maintenance_human_fixture import HumanMaintenanceFixture
from lifecycle_fixture import LifecycleFixture, REALM, call


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
        own_body = own_result = None
        if label == 'committed':
            own_target = copy.deepcopy(target); own_target['origin']['humanSubject'] = account
            own_status, own_current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': own_target}, peer[1], 200)
            test.assertEqual(200, own_status)
            own_body = {'target': own_target, 'operationId': str(uuid.uuid4()), 'expectedState': own_current['state'],
                'change': {'firstName': 'OriginalTenant', 'lastName': native['lastName'], 'email': native['email']}}
            own_status, own_result = HumanMaintenanceFixture.invoke(helper, 'profile', own_body, peer[1], 200)
            test.assertEqual(200, own_status); test.assertEqual('UPDATED', own_result['result'])
            test.assertEqual((200, own_result), HumanMaintenanceFixture.invoke(helper, 'profile', own_body, peer[1], 200))
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 200)
        test.assertEqual(200, status)
        body = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                'change': {'tenantId': '22'}}
        # The current consumed peer is never a PLATFORM reassignment source.
        denied = copy.deepcopy(body); denied['operationId'] = str(uuid.uuid4()); denied['target']['origin']['humanSubject'] = peer[0]
        peer_status, _ = HumanMaintenanceFixture.invoke(helper, 'reassign-tenant', denied, peer[1], 403)
        before_groups = helper.admin('GET', '/users/' + account + '/groups')
        before_roles = helper.admin('GET', '/users/' + account + '/role-mappings')
        status, result = HumanMaintenanceFixture.invoke(helper, 'reassign-tenant', body, primary, 200)
        records[label] = {'status': status, 'preconditions': True, 'peerStatus': peer_status}
        with test.subTest(operation='tenant-reassignment.' + label):
            test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
            test.assertEqual(403, peer_status)
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
            if label == 'committed':
                native = helper.admin('GET', '/users/' + account)
                login_status, login = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
                    {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': native['username'],
                     'password': LifecycleFixture.creation(helper)['account']['password'], 'scope': 'openid'}, form=True)
                test.assertEqual(200, login_status)
                fresh_self = copy.deepcopy(updated); fresh_self['origin'].update(kind='SELF', humanSubject=account)
                old_status, _ = HumanMaintenanceFixture.invoke(helper, 'read', {'target': fresh_self}, peer[1], 403)
                test.assertEqual(403, old_status)
                new_status, new_current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': fresh_self}, login['access_token'], 200)
                records[label]['newTenantSelfReadStatus'] = new_status
                test.assertEqual(200, new_status); test.assertEqual('22', new_current['tenantId'])
                records[label]['oldTokenDeniedNewTokenCurrentTenantVerified'] = True
                before_replay = helper.admin('GET', '/users/' + account)
                revoked_status, revoked = HumanMaintenanceFixture.invoke(helper, 'profile', own_body, login['access_token'], 403)
                records[label]['originalTenantSavedProfileReplayStatus'] = revoked_status
                with test.subTest(operation='tenant-reassignment.current-source-cannot-replay-original-tenant-reach'):
                    test.assertEqual(403, revoked_status); test.assertNotIn('receipt', revoked)
                    test.assertEqual(before_replay, helper.admin('GET', '/users/' + account))
                    records[label]['savedHumanResultRequiresOriginalAndCurrentTargetScope'] = True
    helper.account_id, helper.creation_input = original_account, original_creation
