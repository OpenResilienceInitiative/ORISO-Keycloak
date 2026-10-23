"""Two source-supported identity additions, exact native role union and original-proof lineage."""
import base64
import copy
import json
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
            historical = refused = None
            if label.startswith('PROTECTED'):
                historical = {'target': copy.deepcopy(target), 'operationId': str(uuid.uuid4()),
                    'expectedState': current['state'], 'change': {'firstName': 'BeforeRoleAddition',
                        'lastName': native['lastName'], 'email': native['email']}}
                historical_status, historical_result = HumanMaintenanceFixture.invoke(helper, 'profile', historical, primary, 200)
                test.assertEqual(200, historical_status)
                test.assertEqual((200, historical_result), HumanMaintenanceFixture.invoke(helper, 'profile', historical, primary, 200))
                refused = copy.deepcopy(historical); refused['operationId'] = str(uuid.uuid4()); refused['change']['firstName'] = 'StaleCAS'
                refusal_status, refusal_result = HumanMaintenanceFixture.invoke(helper, 'profile', refused, primary, 409)
                test.assertEqual(409, refusal_status); test.assertEqual('NO_EFFECT', refusal_result['result'])
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
            if historical is not None:
                # The installed dual profile has explicit read/transition rights but no profile
                # write right. A saved UPDATED receipt cannot supply the missing current grant.
                replay_status, replay = HumanMaintenanceFixture.invoke(helper, 'profile', historical, primary, 403)
                records[label]['savedProfileAfterCurrentOperationGrantWithdrawal'] = replay_status
                with test.subTest(operation='profile-transition.saved-updated-requires-current-target-operation-grant'):
                    test.assertEqual(403, replay_status); test.assertNotIn('receipt', replay)
                # Learning the exact permanent refusal needs current read reach, not a newly
                # granted mutation right that the current target deliberately does not have.
                test.assertEqual((409, refusal_result), HumanMaintenanceFixture.invoke(helper, 'profile', refused, primary, 409))
                records[label]['savedNoEffectRequiresCurrentReadWithoutMutationGrant'] = True
    finally:
        helper.account_id, helper.creation_input = old_account, old_creation



def install_self_source(helper, configuration):
    """Explicit source-policy alternative for a second real human; original primary remains default-empty."""
    from test_protected_invitations import HUMAN_PASSWORD
    parent = helper.group_id('/protected-admins')
    helper.admin('POST', '/groups/' + parent + '/children', {'name': 'platform-consultants'})
    group = helper.group_id('/protected-admins/platform-consultants')
    roles = ['agency-admin', 'consultant', 'group-chat-consultant', 'tenant-admin']
    helper.admin('POST', '/groups/' + group + '/role-mappings/realm',
        [helper.admin('GET', '/roles/' + role) for role in roles])
    original = next(profile for profile in configuration['profiles'] if profile['id'] == 'platform-v1')
    desired = copy.deepcopy(original); desired.update(id='platform-consultant-v2', version=2,
        groupId=group, groupPath='/protected-admins/platform-consultants', realmRoles=roles)
    configuration['profiles'].append(desired)
    binding = configuration['bindings'][0]
    binding['protectedProfileIds'].append(desired['id']); binding['protectedProfileIds'].sort()
    binding['accountOperations'].append({'authority': 'PLATFORM',
        'targetProfiles': sorted([original['id'], desired['id']]), 'selfOnly': False,
        'operations': ['account.profile-transition', 'account.read']})
    binding['accountOperations'].append({'authority': 'PLATFORM', 'targetProfiles': [desired['id']],
        'selfOnly': True, 'operations': ['account.email', 'account.locale', 'account.password', 'account.profile', 'account.read']})
    configuration['adoptedAccounts'].append({'accountId': helper.human_subject,
        'protectedProfileId': original['id'], 'profileVersion': original['version']})
    username = 'reviewed-source-variant-' + uuid.uuid4().hex
    helper.admin('POST', '/users', {'username': username, 'enabled': True, 'emailVerified': True,
        'email': username + '@oriso.org', 'firstName': 'Reviewed', 'lastName': 'Source',
        'attributes': {'tenantId': ['0']}, 'credentials': [{'type': 'password', 'value': HUMAN_PASSWORD, 'temporary': False}]})
    users = helper.admin('GET', '/users?username=' + username + '&exact=true'); helper.assertEqual(1, len(users)); account = users[0]['id']
    defaults = helper.admin('GET', '/users/' + account + '/role-mappings/realm')
    if defaults: helper.admin('DELETE', '/users/' + account + '/role-mappings/realm', defaults)
    helper.admin('PUT', '/users/' + account + '/groups/' + original['groupId'])
    explicit = copy.deepcopy(binding); explicit['subject'] = account
    explicit['sourceProfileVariants'] = [{'profileId': desired['id'], 'profileVersion': desired['version']}]
    configuration['bindings'].append(explicit)
    configuration['adoptedAccounts'].append({'accountId': account,
        'protectedProfileId': original['id'], 'profileVersion': original['version']})
    type(helper).variant_source_account = account
    type(helper).variant_source_username = username
    return configuration


def self_source_policy_boundary(test, helper, observed):
    """Declared current policy recovers lost200; missing, stale and extra-grant identities cannot borrow it."""
    import subprocess
    from protected_resources import require_active
    from test_protected_invitations import HUMAN_PASSWORD
    original_account, original_creation = helper.account_id, helper.creation_input
    records = observed['selfSourceLost200PolicyBoundary'] = {}
    def login(username, roles):
        status, result = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
            {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': username,
             'password': HUMAN_PASSWORD, 'scope': 'openid'}, form=True)
        test.assertEqual(200, status)
        encoded = result['access_token'].split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        test.assertEqual(roles, set(claims['realm_access']['roles']))
        info_status, info = call(helper.base, 'GET', '/realms/' + REALM + '/protocol/openid-connect/userinfo', token=result['access_token'])
        test.assertEqual(200, info_status); test.assertEqual(claims['sub'], info['sub'])
        return result['access_token']
    full = {'agency-admin', 'consultant', 'group-chat-consultant', 'tenant-admin'}
    try:
        for label, account in [('declared', type(helper).variant_source_account), ('missing', helper.human_subject)]:
            native = helper.admin('GET', '/users/' + account)
            token = login(native['username'], {'agency-admin', 'tenant-admin'})
            helper.account_id = account; helper.creation_input = {'account': {'username': native['username']}}
            if label == 'missing':
                # The historical fixture starts with direct grants. Establish its predeclared
                # exact target profile without changing the effective original source authority.
                baseline = next(p for p in type(helper).installed_configuration['profiles'] if p['id'] == 'platform-v1')
                direct = helper.admin('GET', '/users/' + account + '/role-mappings/realm')
                test.assertEqual({'agency-admin', 'tenant-admin'}, {r['name'] for r in direct})
                helper.admin('PUT', '/users/' + account + '/groups/' + baseline['groupId'])
                helper.admin('DELETE', '/users/' + account + '/role-mappings/realm', direct)
            target = human_target(helper, account, native); target['origin']['humanSubject'] = account
            read_status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, token, 200)
            test.assertEqual(200, read_status)
            body = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                'change': {'transition': 'ADD_CONSULTANT_IDENTITY', 'profileId': 'platform-consultant-v2', 'profileVersion': 2}}
            status, first = HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, token, 200)
            record = records[label] = {'mutationStatus': status, 'actualRawPlatformAndFullCurrentTargetReadVerified': True}
            with test.subTest(operation='profile-transition.primary-self-source.' + label + '.actual-effect'):
                test.assertEqual(200, status); test.assertEqual('UPDATED', first['result'])
            if status != 200: continue
            fresh = login(native['username'], full)
            old_status, old = HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, token, 403)
            test.assertEqual(403, old_status); test.assertNotIn('receipt', old)
            replay_status, replay = HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, fresh, 200 if label == 'declared' else 403)
            record.update(freshNativeFourRoleTokenVerified=True, staleTokenDenied=True, replayStatus=replay_status)
            if label == 'missing':
                test.assertEqual(403, replay_status); test.assertNotIn('receipt', replay)
                record.update(absentExplicitSourceVariantDenied=True, unsignedStatusCannotClearFrozenPending=True)
                continue
            with test.subTest(operation='profile-transition.primary-self-source.declared.lost200-replay'):
                test.assertEqual(200, replay_status); test.assertEqual(first, replay)
                record['exactSavedReceiptWithCurrentExplicitPolicyVerified'] = True
            if replay_status != 200: return
            before = helper.admin('GET', '/users/' + account); groups = helper.admin('GET', '/users/' + account + '/groups')
            credentials = helper.admin('GET', '/users/' + account + '/credentials')
            test.assertEqual((200, first), HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, fresh, 200))
            test.assertEqual(before, helper.admin('GET', '/users/' + account))
            test.assertEqual(groups, helper.admin('GET', '/users/' + account + '/groups'))
            test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
            require_active('primary-source-variant-restart')
            subprocess.run(['docker', 'restart', type(helper).name], check=True, capture_output=True, timeout=90)
            type(helper).refresh_endpoint('primary-source-variant-restart'); type(helper).ready()
            helper.base = type(helper).base; helper.installer = type(helper).installer
            fresh = login(native['username'], full)
            test.assertEqual((200, first), HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, fresh, 200))
            record['reviewedVariantStartupAndNoSecondEffectVerified'] = True
            from self_profile_operations import account as self_profile
            self_profile(test, helper, 'PROTECTED.PLATFORM_ADMIN_DUAL', account, fresh, observed)
            helper.admin('POST', '/users/' + account + '/role-mappings/realm', [helper.admin('GET', '/roles/user')])
            extra = login(native['username'], full | {'user'})
            denied_status, denied = HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, extra, 403)
            test.assertEqual(403, denied_status); test.assertNotIn('receipt', denied)
            record['extraUnreviewedCurrentGrantDenied'] = True
    finally:
        helper.account_id, helper.creation_input = original_account, original_creation
