"""Current human grants administer reviewed legacy ordinary humans, never arbitrary native roles."""
import base64
import copy
import hashlib
import hmac
import json
import uuid

from lifecycle_fixture import ACTORS, SUBJECTS, CONTEXT_KEY, LifecycleFixture, REALM, call, canonical, mac
from maintenance_human_fixture import HumanMaintenanceFixture
from profile_transition_operations import human_target


def install(cls, helper, config):
    cls.adopted_admin_cases = {}
    for grant in config['adminOperations']:
        if grant['authority'] == 'TENANT_PEER':
            grant['operations'] = [operation for operation in grant['operations'] if operation != 'account.email']
    for label in ['user', 'consultant', 'agency-admin', 'consultant-agency-admin', 'peer-missing-email', 'unreviewed']:
        group = 'consultant' if label in {'peer-missing-email', 'unreviewed'} else label
        username = 'legacy-admin-' + uuid.uuid4().hex
        password = LifecycleFixture.creation(helper)['account']['password']
        helper.admin('POST', '/users', {'username': username, 'enabled': True, 'email': username + '@oriso.org',
            'emailVerified': True, 'firstName': 'Legacy', 'lastName': 'Administered',
            'attributes': {'tenantId': ['17' if label == 'peer-missing-email' else '11']}})
        rows = helper.admin('GET', '/users?username=' + username + '&exact=true'); helper.assertEqual(1, len(rows))
        account = rows[0]['id']; defaults = helper.admin('GET', '/users/' + account + '/role-mappings/realm')
        if defaults: helper.admin('DELETE', '/users/' + account + '/role-mappings/realm', defaults)
        helper.admin('PUT', '/users/' + account + '/groups/' + helper.group_id('/human-roles/' + group))
        helper.admin('PUT', '/users/' + account + '/reset-password', {'type': 'password', 'value': password, 'temporary': False})
        if label != 'unreviewed':
            config['adoptedAccounts'].append({'accountId': account, 'ordinaryProfileId': group + '-v1', 'profileVersion': 1})
        cls.adopted_admin_cases[label] = (account, password)


def updated(test, helper, command, body, result):
    test.assertEqual({'operationId', 'accountId', 'result', 'receipt'}, set(result))
    test.assertEqual('UPDATED', result['result'])
    encoded, signature = result['receipt'].split('.')
    test.assertEqual(hmac.new(CONTEXT_KEY, ('maintenance-operation-receipt\n' + encoded).encode(), hashlib.sha256).hexdigest(), signature)
    expected = {'realmId': helper.realm_id, 'accountId': body['target']['accountId'], 'operationId': body['operationId'],
        'command': command, 'ownerClient': ACTORS['ACCOUNT_ADMIN'][0], 'ownerSubject': SUBJECTS['ACCOUNT_ADMIN'],
        'intentDigest': mac('maintenance-intent', body), 'previousState': body['expectedState'],
        'tenantId': body['target']['tenantId'], 'originDigest': mac('maintenance-origin', body['target']['origin']), 'result': 'UPDATED'}
    raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    test.assertEqual(expected, json.loads(raw)); test.assertEqual(canonical(expected), raw)
    test.assertEqual(body['operationId'], result['operationId']); test.assertEqual(body['target']['accountId'], result['accountId'])


def exercise(test, helper, peer, observed):
    records = observed['adoptedOrdinaryHumanAdmin'] = {}
    original_account, original_creation = helper.account_id, helper.creation_input
    try:
        for group in ['user', 'consultant', 'agency-admin', 'consultant-agency-admin']:
            account, password = type(helper).adopted_admin_cases[group]
            helper.account_id = account; native = helper.admin('GET', '/users/' + account)
            helper.creation_input = {'account': {'username': native['username']}}
            primary = helper.human(record=False); target = human_target(helper, account, native)
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 200)
            record = records[group] = {'readStatus': status, 'reviewedLegacyWithoutCreationAttempt': True,
                'actualCurrentRawPlatformHumanAndExplicitAdminOperations': True}
            with test.subTest(operation='adopted-human-admin.' + group + '.read'):
                test.assertEqual(200, status); test.assertEqual(account, current['id'])
            if status != 200: continue
            def read():
                s, value = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 200)
                test.assertEqual(200, s); return value
            saved = []
            def change(command, patch):
                body = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': read()['state'], 'change': patch}
                s, result = HumanMaintenanceFixture.invoke(helper, command, body, primary, 200)
                test.assertEqual(200, s); updated(test, helper, command, body, result)
                test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, command, body, primary, 200))
                saved.append((command, copy.deepcopy(body), copy.deepcopy(result)))
                return helper.admin('GET', '/users/' + account)
            after = change('profile', {'firstName': 'Reviewed', 'lastName': 'LegacyProfile', 'email': native['email']})
            test.assertEqual('Reviewed', after['firstName']); test.assertEqual('LegacyProfile', after['lastName'])
            email = 'reviewed-legacy-' + uuid.uuid4().hex + '@oriso.org'
            test.assertEqual(email, change('email', {'email': email})['email'])
            test.assertFalse(change('deactivate', {})['enabled'])
            password = 'Reviewed-Legacy-' + uuid.uuid4().hex + '9!'
            test.assertTrue(change('reactivate', {'expectedUsername': native['username'], 'expectedEmail': email, 'password': password})['enabled'])
            status, token = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
                {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': native['username'], 'password': password, 'scope': 'openid'}, form=True)
            test.assertEqual(200, status)
            if group == 'consultant':
                change('ordinary-profile', {'group': '/human-roles/consultant-basic',
                    'profile': {'firstName': 'Combined', 'lastName': 'AtomicLegacy', 'email': email}})
                test.assertEqual(['consultant'], read()['effectiveRoles'])
                change('ordinary-profile', {'group': '/human-roles/consultant'})
                test.assertEqual({'consultant', 'group-chat-consultant'}, set(read()['effectiveRoles']))
            if group in {'consultant', 'agency-admin'}:
                transition = 'ADD_AGENCY_ADMIN_IDENTITY' if group == 'consultant' else 'ADD_CONSULTANT_IDENTITY'
                change('profile-transition', {'transition': transition, 'group': '/human-roles/consultant-agency-admin'})
                test.assertEqual({'consultant', 'group-chat-consultant', 'restricted-agency-admin', 'user-admin'}, set(read()['effectiveRoles']))
                status, fresh = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
                    {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': native['username'], 'password': password, 'scope': 'openid'}, form=True)
                test.assertEqual(200, status)
                self_target = copy.deepcopy(target); self_target['origin'].update(kind='SELF', humanSubject=account, humanAuthority=None)
                test.assertEqual(200, HumanMaintenanceFixture.invoke(helper, 'read', {'target': self_target}, fresh['access_token'], 200)[0])
                record['typedRoleAdditionAndCurrentSelfJoinOriginalAdoptionMacLineage'] = True
            before = helper.admin('GET', '/users/' + account); credentials = helper.admin('GET', '/users/' + account + '/credentials')
            foreign = copy.deepcopy(target); foreign['origin']['humanSubject'] = peer[0]
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': foreign}, primary, 403)[0])
            foreign = copy.deepcopy(target); foreign['origin']['humanSubject'] = peer[0]
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': foreign}, peer[1], 403)[0])
            current_group = helper.admin('GET', '/users/' + account + '/groups')[0]['id']
            wrong_group = helper.group_id('/human-roles/' + ('consultant' if group == 'user' else 'user'))
            helper.admin('DELETE', '/users/' + account + '/groups/' + current_group); helper.admin('PUT', '/users/' + account + '/groups/' + wrong_group)
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 403)[0])
            helper.admin('DELETE', '/users/' + account + '/groups/' + wrong_group); helper.admin('PUT', '/users/' + account + '/groups/' + current_group)
            for command, body, result in saved:
                test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, command, body, primary, 200))
            test.assertEqual(before, helper.admin('GET', '/users/' + account)); test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
            if group == 'consultant-agency-admin':
                helper.admin('DELETE', '/users/' + account)
                helper.admin('POST', '/partialImport', {'ifResourceExists': 'FAIL', 'users': [{'id': account, 'username': native['username'], 'enabled': True,
                    'email': email, 'firstName': 'Recreated', 'lastName': 'Current', 'attributes': {'tenantId': ['11']}}]})
                defaults = helper.admin('GET', '/users/' + account + '/role-mappings/realm')
                if defaults: helper.admin('DELETE', '/users/' + account + '/role-mappings/realm', defaults)
                helper.admin('PUT', '/users/' + account + '/groups/' + current_group)
                fresh = helper.admin('GET', '/users/' + account); test.assertNotEqual(before['createdTimestamp'], fresh['createdTimestamp'])
                test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 403)[0])
                for command, body, result in saved:
                    s, refusal = HumanMaintenanceFixture.invoke(helper, command, body, primary, 403)
                    test.assertEqual(403, s); test.assertNotIn('receipt', refusal)
                test.assertEqual(fresh, helper.admin('GET', '/users/' + account))
                record['sameUuidSameProfileNewIncarnationCannotRecoverOldUpdated'] = True
            record['applicableAdminEffectsUpdated11ExactReplayAndCurrentScopeNegatives'] = True
        account, _ = type(helper).adopted_admin_cases['unreviewed']; helper.account_id = account
        native = helper.admin('GET', '/users/' + account); helper.creation_input = {'account': {'username': native['username']}}
        primary = helper.human(record=False); target = human_target(helper, account, native)
        test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 403)[0])
        account, _ = type(helper).adopted_admin_cases['peer-missing-email']; helper.account_id = account
        native = helper.admin('GET', '/users/' + account); helper.creation_input = {'account': {'username': native['username']}}
        target = human_target(helper, account, native); target['origin']['humanSubject'] = peer[0]
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, peer[1], 200)
        records['peer-read-without-email-grant'] = {'readStatus': status}
        with test.subTest(operation='adopted-human-admin.current-read-without-email-grant'):
            test.assertEqual(200, status)
        if status == 200:
            body = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': {'email': 'denied-' + uuid.uuid4().hex + '@oriso.org'}}
            s, refusal = HumanMaintenanceFixture.invoke(helper, 'email', body, peer[1], 403)
            test.assertEqual(403, s); test.assertNotIn('receipt', refusal); test.assertEqual(native, helper.admin('GET', '/users/' + account))
            records['peer-read-without-email-grant']['currentMutationGrantStillRequired'] = True
        records['unreviewed'] = {'configuredHumanAuthorityAndCurrentNativeRolesDoNotSupplyAdoption': True}
    finally:
        helper.account_id, helper.creation_input = original_account, original_creation
