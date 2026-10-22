"""Two source-supported identity additions, exact native role union and original-proof lineage."""
import copy
import uuid

from lifecycle_fixture import LifecycleFixture, REALM, call
from maintenance_human_fixture import HumanMaintenanceFixture


def committed_kind(test, helper, kind, group):
    creation = LifecycleFixture.creation(helper, kind=kind, group=group)
    attempt = str(uuid.uuid4())
    status, opened = LifecycleFixture.request(helper, 'create', attempt, creation)
    test.assertEqual(201, status)
    status, result = LifecycleFixture.request(helper, 'commit', attempt, LifecycleFixture.finish(helper, creation, opened))
    test.assertEqual(200, status); test.assertEqual('COMMITTED', result['state'])
    return opened['accountId'], creation


def human_target(helper, account, native):
    return {'accountId': account, 'tenantId': native['attributes']['tenantId'][0], 'origin': {
        'kind': 'HUMAN_ADMIN', 'workflowId': str(uuid.uuid4()), 'humanSubject': helper.human_subject,
        'humanIssuer': type(helper).native_issuer, 'humanClient': 'protected-human-web',
        'humanAuthority': 'PROTECTED_ACCOUNT_OPERATIONS_V1'}}


def exercise(test, helper, primary, peer, observed):
    records = observed['profileTransitions'] = {}
    old_account, old_creation = helper.account_id, helper.creation_input
    cases = []
    for kind, group, transition in [('AGENCY_ADMIN', 'agency-admin', 'ADD_CONSULTANT_IDENTITY'),
            ('CONSULTANT', 'consultant', 'ADD_AGENCY_ADMIN_IDENTITY')]:
        account, creation = committed_kind(test, helper, kind, group)
        cases.append(('ORDINARY.' + transition, account, creation, {'transition': transition,
            'group': '/human-roles/consultant-agency-admin'}))
    cases.append(('PROTECTED.ADD_CONSULTANT_IDENTITY', peer[0], None,
        {'transition': 'ADD_CONSULTANT_IDENTITY', 'profileId': 'tenant-consultant-v2', 'profileVersion': 2}))
    try:
        for label, account, creation, change in cases:
            native = helper.admin('GET', '/users/' + account)
            helper.account_id = account; helper.creation_input = creation or {'account': {'username': native['username']}}
            target = human_target(helper, account, native)
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 200)
            test.assertEqual(200, status)
            body = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': change}
            before = helper.admin('GET', '/users/' + account)
            status, result = HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, primary, 200)
            records[label] = {'status': status, 'currentFullProfileAndRawHumanReadVerified': True,
                'unchangedOnMissingReceiver': before == helper.admin('GET', '/users/' + account)}
            required = {'consultant', 'group-chat-consultant'}
            if label.startswith('ORDINARY'): required |= {'restricted-agency-admin', 'user-admin'}
            else: required.add('tenant-admin')
            with test.subTest(operation='profile-transition.' + label):
                test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
                test.assertEqual((status, result), HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, primary, 200))
                status_after, after = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 200)
                test.assertEqual(200, status_after)
                test.assertEqual(required, set(after['effectiveRoles']))
                test.assertTrue(set(current['effectiveRoles']) <= set(after['effectiveRoles']))
                test.assertEqual(target['tenantId'], after['tenantId'])
                test.assertEqual([], helper.admin('GET', '/users/' + account + '/role-mappings/realm'))
                changed = copy.deepcopy(body)
                if label.startswith('ORDINARY'): changed['change']['group'] = '/human-roles/consultant'
                else: changed['change']['profileVersion'] = 1
                conflict_status, conflict = HumanMaintenanceFixture.invoke(helper, 'profile-transition', changed, primary, 409)
                test.assertEqual(409, conflict_status); test.assertNotIn('receipt', conflict)
                records[label]['nativeFullUnionExactRetryAndOriginalProofJoinVerified'] = True
            if status != 200:
                continue
            native = helper.admin('GET', '/users/' + account)
            password = (creation or LifecycleFixture.creation(helper))['account']['password']
            login_status, login = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
                {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': native['username'],
                 'password': password, 'scope': 'openid'}, form=True)
            test.assertEqual(200, login_status)
            self_target = copy.deepcopy(target); self_target['origin'].update(kind='SELF', humanSubject=account,
                humanAuthority=None if label.startswith('ORDINARY') else 'PROTECTED_ACCOUNT_OPERATIONS_V1')
            self_status, current_self = HumanMaintenanceFixture.invoke(helper, 'read', {'target': self_target}, login['access_token'], 200)
            with test.subTest(operation='profile-transition.' + label + '.fresh-self-lineage'):
                test.assertEqual(200, self_status); test.assertEqual(required, set(current_self['effectiveRoles']))
                records[label]['freshHumanCurrentProfileAndOriginalProvenanceVerified'] = True
    finally:
        helper.account_id, helper.creation_input = old_account, old_creation
