"""Explicit installed adoption remains a target selector, never a source authority."""
import copy
import uuid

from lifecycle_fixture import REALM, call
from maintenance_human_fixture import HumanMaintenanceFixture


def install(cls, helper, config, profile_id, tenant):
    username = 'adopted-' + uuid.uuid4().hex
    helper.admin('POST', '/users', {'username': username, 'enabled': True,
        'email': username + '@oriso.org', 'emailVerified': True,
        'firstName': 'Adopted', 'lastName': 'Native', 'attributes': {'tenantId': [str(tenant)]}})
    users = helper.admin('GET', '/users?username=' + username + '&exact=true')
    helper.assertEqual(1, len(users)); account = users[0]['id']
    defaults = helper.admin('GET', '/users/' + account + '/role-mappings/realm')
    if defaults:
        helper.admin('DELETE', '/users/' + account + '/role-mappings/realm', defaults)
    profile = next(p for p in config['profiles'] if p['id'] == profile_id)
    helper.admin('PUT', '/users/' + account + '/groups/' + profile['groupId'])
    config['adoptedAccounts'] = [{'accountId': account, 'protectedProfileId': profile_id, 'profileVersion': profile['version']}]
    cls.adopted_account = account
    cls.adopted_profile = profile_id
    return config


def exercise(test, helper, primary, observed):
    account = type(helper).adopted_account
    old_account, old_creation = helper.account_id, helper.creation_input
    helper.account_id = account
    native = helper.admin('GET', '/users/' + account)
    helper.creation_input = {'account': {'username': native['username']}}
    target = {'accountId': account, 'tenantId': native['attributes']['tenantId'][0], 'origin': {
        'kind': 'HUMAN_ADMIN', 'workflowId': str(uuid.uuid4()), 'humanSubject': helper.human_subject,
        'humanIssuer': type(helper).native_issuer, 'humanClient': 'protected-human-web',
        'humanAuthority': 'PROTECTED_ACCOUNT_OPERATIONS_V1'}}
    try:
        test.assertEqual(403, call(helper.base, 'GET', '/admin/realms/' + REALM + '/users/' + account,
                                   token=helper.token('ACCOUNT_ADMIN'))[0])
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 200)
        observed['explicitAdoption'] = {'preconditions': True, 'readStatus': status}
        with test.subTest(operation='protected.adoption.read'):
            test.assertEqual(200, status); test.assertEqual(account, current['id'])
        wrong = copy.deepcopy(target); wrong['tenantId'] = '987654321'
        test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': wrong}, primary, 403)[0])
        original = copy.deepcopy(native)
        drifted = copy.deepcopy(native); drifted['enabled'] = False
        helper.admin('PUT', '/users/' + account, drifted)
        try:
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 403)[0])
        finally:
            helper.admin('PUT', '/users/' + account, original)
        observed['explicitAdoption']['tenantAndDisabledDriftDenied'] = True
    finally:
        helper.account_id, helper.creation_input = old_account, old_creation
