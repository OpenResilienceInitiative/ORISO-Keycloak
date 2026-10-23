"""Actual SELF password compatibility, native verifier effects and permanently fenced policy refusal."""
import base64
import copy
import hashlib
import hmac
import json
import time
import uuid

from lifecycle_fixture import ACTORS, SUBJECTS, CONTEXT_KEY, LifecycleFixture, REALM, call, canonical, mac
from maintenance_human_fixture import HumanMaintenanceFixture
from profile_transition_operations import committed_kind


def verify_terminal(test, helper, body, result, status):
    test.assertEqual({'operationId', 'accountId', 'result', 'status', 'receipt'}, set(result))
    test.assertEqual(body['operationId'], result['operationId']); test.assertEqual(body['target']['accountId'], result['accountId'])
    test.assertEqual('NO_EFFECT', result['result']); test.assertEqual(status, result['status'])
    encoded, signature = result['receipt'].split('.')
    test.assertEqual(hmac.new(CONTEXT_KEY, ('maintenance-no-effect-receipt/v1\n' + encoded).encode(), hashlib.sha256).hexdigest(), signature)
    payload = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    expected = {'realmId': helper.realm_id, 'accountId': body['target']['accountId'], 'operationId': body['operationId'],
        'command': 'self-password', 'ownerClient': ACTORS['ACCOUNT_ADMIN'][0], 'ownerSubject': SUBJECTS['ACCOUNT_ADMIN'],
        'intentDigest': mac('maintenance-intent', body), 'previousState': body['expectedState'],
        'tenantId': body['target']['tenantId'], 'originDigest': mac('maintenance-origin', body['target']['origin']),
        'result': 'NO_EFFECT', 'status': status}
    test.assertEqual(expected, json.loads(payload)); test.assertEqual(canonical(expected), payload)


def exercise(test, helper, tenant, observed):
    records = observed['actualSelfPassword'] = {}
    original_account, original_creation = helper.account_id, helper.creation_input
    cases = []
    for kind, group in [('ASKER', 'user'), ('CONSULTANT', 'consultant'),
                         ('AGENCY_ADMIN', 'agency-admin'), ('CONSULTANT_AGENCY_ADMIN', 'consultant-agency-admin')]:
        account, creation = committed_kind(test, helper, kind, group)
        cases.append(('ORDINARY.' + ('USER' if kind == 'ASKER' else kind), account, creation['account']['password']))
    initial = LifecycleFixture.creation(helper)['account']['password']
    cases += [('PROTECTED.TENANT_ADMIN_DUAL', tenant[0], initial),
              ('PROTECTED.PLATFORM_ADMIN', type(helper).new_platform_account, initial)]
    def login(username, password):
        return call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
            {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': username,
             'password': password, 'scope': 'openid'}, form=True)
    try:
        for label, account, old_password in cases:
            native = helper.admin('GET', '/users/' + account)
            helper.account_id = account; helper.creation_input = {'account': {'username': native['username']}}
            status, token = login(native['username'], old_password); test.assertEqual(200, status)
            human = token['access_token']; claims = human.split('.')[1]
            claims = json.loads(base64.urlsafe_b64decode(claims + '=' * (-len(claims) % 4)))
            roles = {r['name'] for r in helper.admin('GET', '/users/' + account + '/role-mappings/realm/composite')}
            test.assertEqual(roles, set(claims['realm_access']['roles'])); test.assertEqual(account, claims['sub'])
            work = str(uuid.uuid4())
            target = {'accountId': account, 'tenantId': native['attributes']['tenantId'][0], 'origin': {
                'kind': 'SELF', 'workflowId': work, 'humanSubject': account,
                'humanIssuer': type(helper).native_issuer, 'humanClient': 'protected-human-web',
                'humanAuthority': 'PROTECTED_ACCOUNT_OPERATIONS_V1' if label.startswith('PROTECTED') else None}}
            previous_policy = helper.admin('GET', '').get('passwordPolicy', '')
            hash_boundary = label == 'ORDINARY.USER'
            if hash_boundary:
                password_credentials = [r for r in helper.admin('GET', '/users/' + account + '/credentials') if r['type'] == 'password']
                test.assertEqual(1, len(password_credentials))
                original_algorithm = json.loads(password_credentials[0]['credentialData'])['algorithm']
                changed_algorithm = 'pbkdf2-sha256' if original_algorithm != 'pbkdf2-sha256' else 'argon2'
                helper.admin('PUT', '', {'passwordPolicy': 'hashAlgorithm(' + changed_algorithm + ')'})
            try:
                read_status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 200)
                test.assertEqual(200, read_status); test.assertEqual(account, current['id']); test.assertTrue(current['enabled'])
                test.assertEqual(roles, set(current['effectiveRoles']))
                deadline = int(time.time()) + (5 if label == 'ORDINARY.CONSULTANT' else 180)
                password = 'Actual-Self-Password-' + uuid.uuid4().hex
                body = {'target': target, 'operationId': work, 'expectedState': current['state'],
                    'authorityValidUntil': deadline, 'change': {'currentPassword': old_password, 'password': password, 'temporary': False}}
                status, result = HumanMaintenanceFixture.invoke(helper, 'self-password', body, human, 200)
                record = records[label] = {'mutationStatus': status, 'readStatus': read_status,
                    'actualSubjectTenantFullNativeProfileAndExplicitGrants': True}
                with test.subTest(operation='self-password.' + label + '.actual-effect'):
                    test.assertEqual(200, status); test.assertEqual('UPDATED', result.get('result'))
                if status != 200: continue
                new_status, fresh = login(native['username'], password)
                old_status, _ = login(native['username'], old_password)
                record.update(newPasswordLoginStatus=new_status, oldPasswordLoginStatus=old_status)
                with test.subTest(operation='self-password.' + label + '.new-native-login'):
                    test.assertEqual(200, new_status); test.assertEqual(400, old_status)
                if new_status != 200: continue
                fresh = fresh['access_token']
                credentials = helper.admin('GET', '/users/' + account + '/credentials')
                test.assertEqual(1, len([r for r in credentials if r['type'] == 'password']))
                test.assertNotIn('UPDATE_PASSWORD', helper.admin('GET', '/users/' + account).get('requiredActions', []))
                test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, 'self-password', body, fresh, 200))
                test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
                record['durableChosenPasswordAndExactReplayWithoutSecondEffect'] = True
                if hash_boundary: record['oldHashPolicyCannotOverwriteNewPasswordAfterCommit'] = True
                wrong = copy.deepcopy(body); wrong['operationId'] = str(uuid.uuid4()); wrong['change']['currentPassword'] = 'wrong-current-password'
                read_status, now = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, fresh, 200)
                test.assertEqual(200, read_status); wrong['expectedState'] = now['state']
                wrong['authorityValidUntil'] = int(time.time()) + 180
                wrong_status, wrong_result = HumanMaintenanceFixture.invoke(helper, 'self-password', wrong, fresh, 400)
                test.assertEqual(400, wrong_status); test.assertNotIn('receipt', wrong_result)
                test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
                record['wrongCurrentPasswordUnsignedAndNoEffect'] = True
                stale = copy.deepcopy(body); stale['operationId'] = str(uuid.uuid4())
                stale['authorityValidUntil'] = int(time.time()) + 180
                stale['change']['currentPassword'] = password; stale['change']['password'] = 'Stale-CAS-' + uuid.uuid4().hex
                stale_status, stale_result = HumanMaintenanceFixture.invoke(helper, 'self-password', stale, fresh, 409)
                with test.subTest(operation='self-password.' + label + '.definite-stale-cas-fence'):
                    test.assertEqual(409, stale_status); test.assertEqual('NO_EFFECT', stale_result.get('result'))
                    verify_terminal(test, helper, stale, stale_result, 409)
                    record['definiteStaleCasSignedAndFenced'] = True
                if label in {'ORDINARY.CONSULTANT', 'PROTECTED.TENANT_ADMIN_DUAL'}:
                    policy_body = copy.deepcopy(wrong); policy_body['operationId'] = str(uuid.uuid4())
                    policy_body['change'] = {'currentPassword': password, 'password': 'Policy-short-42', 'temporary': False}
                    policy = helper.admin('GET', '').get('passwordPolicy', '')
                    stored_algorithm = json.loads(next(c for c in credentials if c['type'] == 'password')['credentialData'])['algorithm']
                    other_algorithm = 'pbkdf2-sha256' if stored_algorithm != 'pbkdf2-sha256' else 'argon2'
                    helper.admin('PUT', '', {'passwordPolicy': 'hashAlgorithm(' + other_algorithm + ') and length(100)'})
                    try:
                        policy_status, terminal = HumanMaintenanceFixture.invoke(helper, 'self-password', policy_body, fresh, 400)
                        test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
                        record['policyStatus'] = policy_status
                        with test.subTest(operation='self-password.' + label + '.prewrite-policy-fence'):
                            test.assertEqual(400, policy_status); test.assertEqual('NO_EFFECT', terminal.get('result'))
                            # The committing refusal must not run a queued old-password hash refresh.
                            verify_terminal(test, helper, policy_body, terminal, 400)
                    finally:
                        helper.admin('PUT', '', {'passwordPolicy': policy})
                    if terminal.get('result') == 'NO_EFFECT':
                        test.assertEqual((400, terminal), HumanMaintenanceFixture.invoke(helper, 'self-password', policy_body, fresh, 400))
                        test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
                        record['policy400RestoredPolicyNeverAppliesFrozenIntent'] = True
                if label == 'ORDINARY.CONSULTANT':
                    while time.time() <= deadline: time.sleep(0.1)
                    login_status, live = login(native['username'], password); test.assertEqual(200, login_status)
                    test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, 'self-password', body, live['access_token'], 200))
                    expired = copy.deepcopy(wrong); expired['operationId'] = str(uuid.uuid4()); expired['authorityValidUntil'] = deadline
                    expired_status, expired_result = HumanMaintenanceFixture.invoke(helper, 'self-password', expired, live['access_token'], 400)
                    test.assertEqual(400, expired_status); test.assertNotIn('receipt', expired_result)
                    record['exactSavedAfterOriginalDeadlineAndExpiredAbsentDenial'] = True
                    primary = helper.human(record=False)
                    admin_target = copy.deepcopy(target); admin_target['origin'].update(kind='HUMAN_ADMIN',
                        workflowId=str(uuid.uuid4()), humanSubject=helper.human_subject,
                        humanAuthority='PROTECTED_ACCOUNT_OPERATIONS_V1')
                    for group in ['consultant-basic', 'consultant']:
                        read_status, current_admin = HumanMaintenanceFixture.invoke(helper, 'read', {'target': admin_target}, primary, 200)
                        test.assertEqual(200, read_status)
                        profile_body = {'target': admin_target, 'operationId': str(uuid.uuid4()),
                            'expectedState': current_admin['state'], 'change': {'group': '/human-roles/' + group}}
                        changed_status, changed = HumanMaintenanceFixture.invoke(helper, 'ordinary-profile', profile_body, primary, 200)
                        test.assertEqual(200, changed_status); test.assertEqual('UPDATED', changed['result'])
                        login_status, changed_human = login(native['username'], password); test.assertEqual(200, login_status)
                        result_status, result_body = HumanMaintenanceFixture.invoke(helper, 'self-password', body, changed_human['access_token'], 403 if group == 'consultant-basic' else 200)
                        test.assertEqual(403 if group == 'consultant-basic' else 200, result_status)
                        if group == 'consultant-basic': test.assertNotIn('receipt', result_body)
                        else: test.assertEqual(result, result_body)
                        test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
                    record['currentExplicitPasswordGrantWithdrawalDeniesSavedThenReviewedRestorationRecovers'] = True
                if label == 'PROTECTED.TENANT_ADMIN_DUAL':
                    before_disabled = helper.admin('GET', '/users/' + account)
                    disabled = copy.deepcopy(before_disabled); disabled['enabled'] = False
                    helper.admin('PUT', '/users/' + account, disabled)
                    try:
                        denied_status, denied = HumanMaintenanceFixture.invoke(helper, 'self-password', body, fresh, 403)
                        test.assertEqual(403, denied_status); test.assertNotIn('receipt', denied)
                        test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
                    finally:
                        helper.admin('PUT', '/users/' + account, before_disabled)
                    login_status, current_self = login(native['username'], password); test.assertEqual(200, login_status)
                    test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, 'self-password', body, current_self['access_token'], 200))
                    record['disabledCurrentProtectedSelfCannotRecoverSavedReceipt'] = True
            finally:
                helper.admin('PUT', '', {'passwordPolicy': previous_policy})
    finally:
        helper.account_id, helper.creation_input = original_account, original_creation
