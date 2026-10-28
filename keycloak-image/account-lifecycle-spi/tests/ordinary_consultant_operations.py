"""Measured restricted Consultant edits and explicitly declared own Consultant grants."""
import copy
import uuid

from lifecycle_fixture import REALM, call
from maintenance_human_fixture import HumanMaintenanceFixture
from profile_transition_operations import committed_kind, human_target


def install(helper, config):
    profiles = config['ordinaryProfiles']
    full = next(p for p in profiles if p['id'] == 'consultant-agency-admin-v1')
    helper.admin('POST', '/groups/' + helper.group_id('/human-roles') + '/children',
                 {'name': 'consultant-agency-admin-unacknowledged'})
    unack = copy.deepcopy(full)
    unack.update(id='combined-unacknowledged-v1',
                 groupPath='/human-roles/consultant-agency-admin-unacknowledged',
                 groupId=helper.group_id('/human-roles/consultant-agency-admin-unacknowledged'))
    helper.admin('POST', '/groups/' + unack['groupId'] + '/role-mappings/realm',
                 [helper.admin('GET', '/roles/' + role) for role in unack['realmRoles']])
    profiles.append(unack)
    sources = ['agency-admin-v1', 'consultant-agency-admin-v1', 'consultant-agency-admin-basic-v1']
    config['ordinaryAdminOperations'][0]['sourceProfiles'] = sources.copy()
    config['ordinaryAdminOperations'] += [
        {'sourceProfiles': sources.copy(),
         'targetProfiles': ['consultant-v1', 'consultant-basic-v1',
                            'consultant-agency-admin-v1', 'consultant-agency-admin-basic-v1'],
         'operations': ['account.read', 'account.profile', 'account.ordinary-profile']},
        {'sourceProfiles': sources.copy(), 'targetProfiles': sources.copy(),
         'operations': ['account.read', 'account.profile-transition']},
    ]


def login(test, helper, account, creation):
    native = helper.admin('GET', '/users/' + account)
    status, value = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
                         {'grant_type': 'password', 'client_id': 'protected-human-web',
                          'username': native['username'], 'password': creation['account']['password'],
                          'scope': 'openid'}, form=True)
    test.assertEqual(200, status)
    return value['access_token']


def target(helper, account, source):
    value = human_target(helper, account, helper.admin('GET', '/users/' + account))
    value['origin'].update(humanSubject=source, humanAuthority='ORDINARY_ACCOUNT_OPERATIONS_V1')
    return value


def exercise(test, helper, primary, observed):
    records = observed['ordinaryConsultantMatrix'] = {}
    old = helper.account_id, helper.creation_input
    try:
        source, creation = committed_kind(test, helper, 'AGENCY_ADMIN', 'agency-admin')
        human = login(test, helper, source, creation)
        for kind, group, desired in [('CONSULTANT', 'consultant', 'consultant-basic'),
                                     ('CONSULTANT_AGENCY_ADMIN', 'consultant-agency-admin', 'consultant-agency-admin-basic')]:
            account, creation = committed_kind(test, helper, kind, group)
            helper.account_id, helper.creation_input = account, creation
            selected = target(helper, account, source)
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': selected}, human, 200)
            test.assertEqual(200, status)
            profile = {'firstName': 'Restricted', 'lastName': 'Reviewed', 'email': 'edit-' + uuid.uuid4().hex + '@oriso.org'}
            body = {'target': selected, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': profile}
            status, result = HumanMaintenanceFixture.invoke(helper, 'profile', body, human, 200)
            test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
            test.assertEqual((status, result), HumanMaintenanceFixture.invoke(helper, 'profile', body, human, 200))
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': selected}, human, 200)
            test.assertEqual(profile['email'], current['email'])
            body = {'target': selected, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                    'change': {'group': '/human-roles/' + desired, 'profile': profile}}
            status, result = HumanMaintenanceFixture.invoke(helper, 'ordinary-profile', body, human, 200)
            test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
            test.assertEqual((status, result), HumanMaintenanceFixture.invoke(helper, 'ordinary-profile', body, human, 200))
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': selected, 'include': 'TWO_FACTOR_STATUS_V1'}, human, 200)
            test.assertEqual(200, status)
            expected = {'consultant'} | ({'restricted-agency-admin', 'user-admin'} if kind == 'CONSULTANT_AGENCY_ADMIN' else set())
            test.assertEqual(expected, set(current['effectiveRoles']))
            test.assertEqual({'configured': False, 'active': False}, current['twoFactor'])
            if kind == 'CONSULTANT_AGENCY_ADMIN':
                denied = {'target': selected, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': {}}
                test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'deactivate', denied, human, 403)[0])
                test.assertTrue(helper.admin('GET', '/users/' + account)['enabled'])
            records[kind] = {'profileEmailAndExactRetry': True, 'groupChatOnlyPreservesIdentityAndRetry': True,
                             'nonsecretFactors': True, 'combinedDeactivationClosed': kind == 'CONSULTANT_AGENCY_ADMIN'}
        peer, peer_creation = committed_kind(test, helper, 'AGENCY_ADMIN', 'agency-admin')
        helper.account_id, helper.creation_input = peer, peer_creation
        test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': target(helper, peer, source)}, human, 403)[0])
        records['peerAgencyAdmin'] = {'readClosed': True}
        for label in ('consultant', 'consultant-agency-admin'):
            account = type(helper).adopted_admin_cases[label][0]
            helper.account_id = account
            helper.creation_input = {'account': {'username': helper.admin('GET', '/users/' + account)['username']}}
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target(helper, account, source)}, human, 200)
            test.assertEqual(200, status); test.assertEqual(account, current['id'])
            records['adopted-' + label] = {'originalAdoptionWithOrdinarySourceRead': True}
        for desired in ('consultant-agency-admin', 'consultant-agency-admin-basic'):
            account, creation = committed_kind(test, helper, 'AGENCY_ADMIN', 'agency-admin')
            helper.account_id, helper.creation_input = account, creation
            human = login(test, helper, account, creation)
            selected = target(helper, account, account)
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': selected}, human, 200)
            test.assertEqual(200, status)
            body = {'target': selected, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                    'change': {'transition': 'ADD_CONSULTANT_IDENTITY', 'group': '/human-roles/consultant-agency-admin-unacknowledged'}}
            before = helper.admin('GET', '/users/' + account)
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, human, 403)[0])
            test.assertEqual(before, helper.admin('GET', '/users/' + account))
            test.assertEqual(['/human-roles/agency-admin'], [g['path'] for g in helper.admin('GET', '/users/' + account + '/groups')])
            body['operationId'] = str(uuid.uuid4()); body['change']['group'] = '/human-roles/' + desired
            status, result = HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, human, 200)
            test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, human, 403)[0])
            fresh = login(test, helper, account, creation)
            test.assertEqual((status, result), HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, fresh, 200))
            status, after = HumanMaintenanceFixture.invoke(helper, 'read', {'target': selected}, fresh, 200)
            test.assertEqual(200, status)
            expected = {'consultant', 'restricted-agency-admin', 'user-admin'} | ({'group-chat-consultant'} if desired.endswith('-admin') else set())
            test.assertEqual(expected, set(after['effectiveRoles']))
            records['own-' + desired] = {'missingDeclaredVariantDeniedBeforeEffect': True, 'actualGrant': True,
                                         'staleTokenRefused': True, 'freshNativeExactReplay': True}
    finally:
        helper.account_id, helper.creation_input = old
