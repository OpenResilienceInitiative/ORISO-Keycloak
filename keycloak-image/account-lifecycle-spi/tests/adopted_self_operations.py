"""Reviewed legacy ordinary humans retain SELF operations without creation provenance."""
import copy
from email import policy
from email.parser import BytesParser
import hashlib
import hmac
import re
import struct
import time
import uuid

from lifecycle_fixture import LifecycleFixture, REALM, call
from maintenance_human_fixture import HumanMaintenanceFixture
from test_otp_scoped import ScopedOtpRead

OTP = ['otp.read', 'otp.app-setup', 'otp.delete', 'otp.email-start', 'otp.email-finish']


def install(cls, helper, config):
    password = LifecycleFixture.creation(helper)['account']['password']
    cls.adopted_self_cases = {}
    for profile in config['ordinaryProfiles']:
        if profile['id'] != 'consultant-basic-v1':
            profile['selfOperations'] = sorted(set(profile['selfOperations'] + OTP))
    for group in ['user', 'consultant', 'agency-admin', 'consultant-agency-admin', 'consultant-basic', 'unreviewed']:
        username = 'legacy-self-' + uuid.uuid4().hex
        helper.admin('POST', '/users', {'username': username, 'enabled': True, 'email': username + '@oriso.org',
            'emailVerified': True, 'firstName': 'Legacy', 'lastName': 'Self', 'attributes': {'tenantId': ['11']}})
        accounts = helper.admin('GET', '/users?username=' + username + '&exact=true'); helper.assertEqual(1, len(accounts))
        account = accounts[0]['id']; defaults = helper.admin('GET', '/users/' + account + '/role-mappings/realm')
        if defaults: helper.admin('DELETE', '/users/' + account + '/role-mappings/realm', defaults)
        actual_group = 'consultant' if group == 'unreviewed' else group
        helper.admin('PUT', '/users/' + account + '/groups/' + helper.group_id('/human-roles/' + actual_group))
        helper.admin('PUT', '/users/' + account + '/reset-password', {'type': 'password', 'value': password, 'temporary': False})
        if group != 'unreviewed':
            config['adoptedAccounts'].append({'accountId': account, 'ordinaryProfileId': group + '-v1', 'profileVersion': 1})
        cls.adopted_self_cases[group] = (account, password)


def login(test, helper, native, password):
    status, token = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
        {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': native['username'],
         'password': password, 'scope': 'openid'}, form=True)
    test.assertEqual(200, status)
    return token['access_token']


def own(helper, account):
    return {'accountId': account, 'tenantId': '11', 'origin': {'kind': 'SELF', 'workflowId': str(uuid.uuid4()),
        'humanSubject': account, 'humanIssuer': type(helper).native_issuer,
        'humanClient': 'protected-human-web', 'humanAuthority': None}}


def exercise(test, helper, observed):
    records = observed['adoptedOrdinarySelf'] = {}
    original_account, original_creation = helper.account_id, helper.creation_input
    try:
        for group in ['user', 'consultant', 'agency-admin', 'consultant-agency-admin']:
            account, password = type(helper).adopted_self_cases[group]
            helper.account_id = account; native = helper.admin('GET', '/users/' + account)
            helper.creation_input = {'account': {'username': native['username']}}
            human = login(test, helper, native, password); target = own(helper, account)
            before = helper.admin('GET', '/users/' + account); credentials = helper.admin('GET', '/users/' + account + '/credentials')
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 200)
            otp_status, setup = ScopedOtpRead.scoped_read(helper, human, target, 200)
            record = records[group] = {'readStatus': status, 'otpReadStatus': otp_status,
                'reviewedLegacyAccountWithoutCreationAttempt': True, 'actualRawSelfLogin': True}
            if group != 'user':
                deletion = copy.deepcopy(target); deletion['origin'].update(kind='DELETION', humanSubject=None,
                    humanIssuer=None, humanClient=None, humanAuthority=None)
                test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': deletion}, None, 403)[0])
                denied = {'target': deletion, 'operationId': str(uuid.uuid4()), 'expectedState': current.get('state', '0' * 64), 'change': {}}
                test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'delete', denied, None, 403)[0])
                test.assertEqual(before, helper.admin('GET', '/users/' + account))
                record['adoptedDeletionStillUserOnly'] = True
            with test.subTest(operation='adopted-self.' + group + '.read'):
                test.assertEqual(200, status); test.assertEqual(account, current['id'])
            with test.subTest(operation='adopted-self.' + group + '.otp-read'):
                test.assertEqual(200, otp_status); test.assertFalse(setup['otpSetup']); test.assertTrue(setup['otpSecret'])
            if status != 200 or otp_status != 200:
                test.assertEqual(before, helper.admin('GET', '/users/' + account))
                test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
                continue
            roles = {r['name'] for r in helper.admin('GET', '/users/' + account + '/role-mappings/realm/composite')}
            test.assertEqual(roles, set(current['effectiveRoles']))
            def read():
                s, value = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 200)
                test.assertEqual(200, s); return value
            saved = []
            changes = [('locale', {'locale': 'en'})] if group == 'user' else []
            if group in {'consultant', 'consultant-agency-admin'}:
                changes += [('profile', {'firstName': 'LegacySelf', 'lastName': 'Profile', 'email': native['email']}),
                    ('email', {'firstName': 'LegacySelf', 'lastName': 'Combined', 'email': 'legacy-combined-' + uuid.uuid4().hex + '@oriso.org'}),
                    ('locale', {'locale': 'en'})]
            changes += [('email', {'email': 'legacy-single-' + uuid.uuid4().hex + '@oriso.org'})] if group != 'user' else []
            for command, change in changes:
                body = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': read()['state'], 'change': change}
                s, result = HumanMaintenanceFixture.invoke(helper, command, body, human, 200)
                test.assertEqual(200, s); test.assertEqual('UPDATED', result['result'])
                after = helper.admin('GET', '/users/' + account)
                for key, value in change.items():
                    test.assertEqual(value, read()['preferredLanguage'] if key == 'locale' else after.get(key))
                test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
                test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, command, body, human, 200))
                saved.append((command, copy.deepcopy(body), copy.deepcopy(result)))
            changed_password = 'Legacy-Self-' + uuid.uuid4().hex + '9!'
            body = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': read()['state'],
                'authorityValidUntil': int(time.time()) + 180,
                'change': {'currentPassword': password, 'password': changed_password, 'temporary': False}}
            s, result = HumanMaintenanceFixture.invoke(helper, 'self-password', body, human, 200)
            test.assertEqual(200, s); test.assertEqual('UPDATED', result['result'])
            human = login(test, helper, native, changed_password)
            test.assertEqual(400, call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
                {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': native['username'],
                 'password': password, 'scope': 'openid'}, form=True)[0])
            after_password = helper.admin('GET', '/users/' + account + '/credentials')
            test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, 'self-password', body, human, 200))
            test.assertEqual(after_password, helper.admin('GET', '/users/' + account + '/credentials'))
            saved.append(('self-password', copy.deepcopy(body), copy.deepcopy(result)))
            s, setup = ScopedOtpRead.scoped_read(helper, human, target, 200); test.assertEqual(200, s)
            seed = setup['otpSecret']; digest = hmac.new(seed.encode(), struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest(); offset = digest[-1] & 15
            code = str((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)
            app = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': read()['state'],
                'otp': {'initialCode': code, 'secret': seed, 'email': None}}
            saved_otp = []
            s, result = ScopedOtpRead.scoped_mutation(helper, human, app, 'otp.app-setup', 'PUT', 'setup-otp', 201)
            test.assertEqual(201, s); test.assertEqual(1, len([c for c in helper.admin('GET', '/users/' + account + '/credentials') if c['type'] == 'otp']))
            test.assertEqual((201, result), ScopedOtpRead.scoped_mutation(helper, human, app, 'otp.app-setup', 'PUT', 'setup-otp', 201))
            saved_otp.append(('otp.app-setup', 'PUT', 'setup-otp', copy.deepcopy(app)))
            delete = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': read()['state'], 'otp': None}
            s, result = ScopedOtpRead.scoped_mutation(helper, human, delete, 'otp.delete', 'DELETE', 'delete-otp', 200)
            test.assertEqual(200, s); test.assertFalse(any(c['type'] == 'otp' for c in helper.admin('GET', '/users/' + account + '/credentials')))
            test.assertEqual((200, result), ScopedOtpRead.scoped_mutation(helper, human, delete, 'otp.delete', 'DELETE', 'delete-otp', 200))
            saved_otp.append(('otp.delete', 'DELETE', 'delete-otp', copy.deepcopy(delete)))
            mail_before = len(helper.mail.messages); destination = 'legacy-mfa-' + uuid.uuid4().hex + '@oriso.org'
            start = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': read()['state'],
                'authorityValidUntil': int(time.time()) + 180, 'otp': {'initialCode': None, 'secret': None, 'email': destination}}
            test.assertEqual(202, ScopedOtpRead.scoped_mutation(helper, human, start, 'otp.email-start', 'PUT', 'send-verification-mail', 202)[0])
            s, delivered = ScopedOtpRead.scoped_mutation(helper, human, start, 'otp.email-start', 'PUT', 'send-verification-mail', 200)
            test.assertEqual(200, s); test.assertEqual('SENT', delivered['deliveryState']); test.assertEqual(mail_before + 1, len(helper.mail.messages))
            test.assertEqual((200, delivered), ScopedOtpRead.scoped_mutation(helper, human, start, 'otp.email-start', 'PUT', 'send-verification-mail', 200))
            test.assertEqual(mail_before + 1, len(helper.mail.messages))
            saved_otp.append(('otp.email-start', 'PUT', 'send-verification-mail', copy.deepcopy(start)))
            codes = set()
            for part in BytesParser(policy=policy.default).parsebytes(helper.mail.messages[-1]).walk():
                if part.get_content_type() in {'text/plain', 'text/html'}:
                    codes.update(re.findall(r'(?<![0-9])[0-9]{6}(?![0-9])', part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')))
            test.assertEqual(1, len(codes))
            finish = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': read()['state'],
                'emailStartOperationId': start['operationId'], 'otp': {'initialCode': next(iter(codes)), 'secret': None, 'email': None}}
            s, result = ScopedOtpRead.scoped_mutation(helper, human, finish, 'otp.email-finish', 'POST', 'setup-otp-mail', 201)
            test.assertEqual(201, s); test.assertEqual(destination, helper.admin('GET', '/users/' + account)['email'])
            test.assertEqual((201, result), ScopedOtpRead.scoped_mutation(helper, human, finish, 'otp.email-finish', 'POST', 'setup-otp-mail', 201))
            saved_otp.append(('otp.email-finish', 'POST', 'setup-otp-mail', copy.deepcopy(finish)))
            record['supportedProfileEmailLocalePasswordAndAllFiveOtpEffectsExactRetries'] = True
            # Clear only this fixture's factors so a fresh real bearer can test current profile/incarnation.
            for c in helper.admin('GET', '/users/' + account + '/credentials'):
                if c['type'] in {'otp', 'MAIL_OTP_CM'}: helper.admin('DELETE', '/users/' + account + '/credentials/' + c['id'])
            current_group = helper.group_id('/human-roles/' + group); foreign_group = helper.group_id('/human-roles/' + ('user' if group != 'user' else 'consultant'))
            helper.admin('DELETE', '/users/' + account + '/groups/' + current_group); helper.admin('PUT', '/users/' + account + '/groups/' + foreign_group)
            changed_human = login(test, helper, native, changed_password)
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, changed_human, 403)[0])
            test.assertEqual(403, ScopedOtpRead.scoped_read(helper, changed_human, target, 403)[0])
            for operation, method, route, frozen in saved_otp:
                s, refusal = ScopedOtpRead.scoped_mutation(helper, changed_human, frozen, operation, method, route, 403)
                record.setdefault('currentForeignProfileSavedOtpStatus', {})[operation] = s
                with test.subTest(operation='adopted-self.' + group + '.current-profile.' + operation):
                    test.assertEqual(403, s); test.assertNotIn('receipt', refusal)
            helper.admin('DELETE', '/users/' + account + '/groups/' + foreign_group); helper.admin('PUT', '/users/' + account + '/groups/' + current_group)
            human = login(test, helper, native, changed_password); test.assertEqual(200, HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 200)[0])
            if group == 'consultant':
                old = helper.admin('GET', '/users/' + account); helper.admin('DELETE', '/users/' + account)
                helper.admin('POST', '/partialImport', {'ifResourceExists': 'FAIL', 'users': [{'id': account, 'username': old['username'], 'enabled': True,
                    'email': old['email'], 'firstName': 'New', 'lastName': 'Incarnation', 'attributes': {'tenantId': ['11']}}]})
                defaults = helper.admin('GET', '/users/' + account + '/role-mappings/realm')
                if defaults: helper.admin('DELETE', '/users/' + account + '/role-mappings/realm', defaults)
                helper.admin('PUT', '/users/' + account + '/groups/' + current_group)
                helper.admin('PUT', '/users/' + account + '/reset-password', {'type': 'password', 'value': changed_password, 'temporary': False})
                fresh = helper.admin('GET', '/users/' + account); test.assertNotEqual(old['createdTimestamp'], fresh['createdTimestamp'])
                human = login(test, helper, fresh, changed_password); fresh_credentials = helper.admin('GET', '/users/' + account + '/credentials')
                test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 403)[0])
                test.assertEqual(403, ScopedOtpRead.scoped_read(helper, human, target, 403)[0])
                for command, frozen, result in saved:
                    s, refusal = HumanMaintenanceFixture.invoke(helper, command, frozen, human, 403)
                    test.assertEqual(403, s); test.assertNotIn('receipt', refusal)
                for operation, method, route, frozen in saved_otp:
                    s, refusal = ScopedOtpRead.scoped_mutation(helper, human, frozen, operation, method, route, 403)
                    record.setdefault('newIncarnationSavedOtpStatus', {})[operation] = s
                    with test.subTest(operation='adopted-self.' + group + '.new-incarnation.' + operation):
                        test.assertEqual(403, s); test.assertNotIn('receipt', refusal)
                test.assertEqual(fresh, helper.admin('GET', '/users/' + account)); test.assertEqual(fresh_credentials, helper.admin('GET', '/users/' + account + '/credentials'))
                record['sameUuidSameFullRolesFreshBearerCannotRecoverOrMutateOldIncarnation'] = True
            record['currentForeignProfileDeniedThenExactReviewedProfileRestored'] = True
        for group in ['unreviewed', 'consultant-basic']:
            account, password = type(helper).adopted_self_cases[group]
            helper.account_id = account; native = helper.admin('GET', '/users/' + account); helper.creation_input = {'account': {'username': native['username']}}
            human = login(test, helper, native, password); target = own(helper, account)
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 403 if group == 'unreviewed' else 200)
            with test.subTest(operation='adopted-self.' + group + '.authority-boundary'):
                test.assertEqual(403 if group == 'unreviewed' else 200, status)
            test.assertEqual(403, ScopedOtpRead.scoped_read(helper, human, target, 403)[0])
            body = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': current.get('state', '0' * 64),
                'authorityValidUntil': int(time.time()) + 180, 'change': {'currentPassword': password, 'password': 'Denied-' + uuid.uuid4().hex + '9!', 'temporary': False}}
            before = helper.admin('GET', '/users/' + account + '/credentials')
            s, refused = HumanMaintenanceFixture.invoke(helper, 'self-password', body, human, 403)
            test.assertEqual(403, s); test.assertNotIn('receipt', refused); test.assertEqual(before, helper.admin('GET', '/users/' + account + '/credentials'))
            records[group] = {'nativeRolesAndRawSelfInsufficient': True, 'missingAdoptionOrSeparateLogicalGrantDenied': True}
    finally:
        helper.account_id, helper.creation_input = original_account, original_creation
