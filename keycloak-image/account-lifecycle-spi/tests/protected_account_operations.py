"""Actual committed protected self on the original OTP route; no diagnostic endpoint."""
import base64
import copy
import hashlib
import hmac
import struct
import json
import time
import os
from pathlib import Path
import uuid
from unittest.mock import patch

from lifecycle_fixture import REALM, ACTORS, SUBJECTS, IMAGE, call
from protected_otp_bootstrap import BootstrapFixture
from protected_peer_readiness import PeerFixture, PeerReadiness, PROFILE, POLICY, TENANT
from test_otp_scoped import ScopedOtpRead
from maintenance_human_fixture import HumanMaintenanceFixture
from test_protected_invitations import ProtectedInvitations


class OperationFixture(BootstrapFixture, PeerFixture):
    @classmethod
    def prepare_installation(cls, helper, configuration):
        value = PeerFixture.prepare_installation.__func__(cls, helper, configuration)
        value['peerDelegationPolicies'][0]['accountOperations'] = [{
            'authority': 'TENANT_PEER', 'targetProfiles': [PROFILE], 'selfOnly': True,
            'operations': ['account.read', 'otp.app-setup', 'otp.delete', 'otp.email-finish', 'otp.email-start', 'otp.read'],
        }]
        value['peerDelegationPolicies'][0]['accountOperations'][0]['operations'].append('account.password')
        value['peerDelegationPolicies'][0]['accountOperations'][0]['operations'].sort()
        value['peerDelegationPolicies'][0]['accountOperations'].append({
            'authority': 'TENANT_PEER', 'targetProfiles': [PROFILE], 'selfOnly': True,
            'operations': ['account.profile']})
        value['bindings'][0]['accountOperations'] = [{
            'authority': 'PLATFORM', 'targetProfiles': ['platform-v1'], 'selfOnly': True,
            'operations': ['account.read', 'otp.app-setup', 'otp.delete', 'otp.email-finish', 'otp.email-start', 'otp.read'],
        }, {
            'authority': 'PLATFORM', 'targetProfiles': ['platform-v1', PROFILE], 'selfOnly': False,
            'operations': ['account.email', 'account.profile', 'account.read'],
        }]
        value['bindings'][0]['accountOperations'][0]['operations'].append('account.password')
        value['bindings'][0]['accountOperations'][0]['operations'].sort()
        value['bindings'][0]['accountOperations'].append({
            'authority': 'PLATFORM', 'targetProfiles': [PROFILE], 'selfOnly': False,
            'operations': ['account.deactivate', 'account.reactivate', 'account.reassign-tenant']})
        value['bindings'][0]['accountOperations'].append({
            'authority': 'PLATFORM', 'targetProfiles': ['platform-v1'], 'selfOnly': False,
            'operations': ['account.deactivate', 'account.reactivate']})
        value['workflowOperations'] = [{'kind': 'INACTIVITY', 'targetProfiles': [PROFILE, 'platform-v1'],
            'operations': ['account.deactivate', 'account.reactivate', 'account.read']}]
        parent = helper.group_id('/protected-admins')
        helper.admin('POST', '/groups/' + parent + '/children', {'name': 'tenant-consultants'})
        group = helper.group_id('/protected-admins/tenant-consultants')
        roles = ['consultant', 'group-chat-consultant', 'tenant-admin']
        helper.admin('POST', '/groups/' + group + '/role-mappings/realm',
            [helper.admin('GET', '/roles/' + role) for role in roles])
        dual = copy.deepcopy(next(profile for profile in value['profiles'] if profile['id'] == PROFILE))
        dual.update(id='tenant-consultant-v2', version=2, groupId=group,
            groupPath='/protected-admins/tenant-consultants', realmRoles=roles)
        value['profiles'].append(dual)
        value['bindings'][0]['protectedProfileIds'].append(dual['id']); value['bindings'][0]['protectedProfileIds'].sort()
        value['bindings'][0]['accountOperations'].append({'authority': 'PLATFORM',
            'targetProfiles': sorted([PROFILE, dual['id']]), 'selfOnly': False,
            'operations': ['account.profile-transition', 'account.read']})
        value['bindings'][0]['accountOperations'][2]['targetProfiles'].append(dual['id'])
        value['bindings'][0]['accountOperations'][2]['targetProfiles'].sort()
        current_peer = copy.deepcopy(value['peerDelegationPolicies'][0])
        current_peer.update(id='own-tenant-consultant-v2', sourceProfileId=dual['id'],
            sourceProfileVersion=2, realmRoles=roles, protectedProfileIds=sorted([PROFILE, dual['id']]))
        current_peer['accountOperations'][0]['targetProfiles'] = sorted([PROFILE, dual['id']])
        current_peer['accountOperations'].append({'authority': 'TENANT_PEER', 'targetProfiles': [dual['id']],
            'selfOnly': True, 'operations': ['account.email', 'account.locale', 'account.profile']})
        value['peerDelegationPolicies'].append(current_peer)
        value['workflowOperations'][0]['targetProfiles'].append(dual['id'])
        value['workflowOperations'].append({'kind': 'IMPORT', 'targetProfiles': [PROFILE, dual['id']],
            'operations': ['account.read']})
        from ordinary_admin_operations import install_policy
        from protected_adoption_operations import install
        install_policy(cls, helper, value)
        value = install(cls, helper, value, PROFILE, TENANT)
        from profile_transition_operations import install_self_source
        value = install_self_source(helper, value)
        fixture = Path(os.environ.get('SCOPED_OTP_READY_FIXTURE_JAR', ''))
        if not fixture.is_file(): raise AssertionError('Existing isolated native observer JAR required')
        command = cls.command.copy(); index = command.index(IMAGE)
        command[index:index] = ['-v', str(fixture.resolve()) + ':/opt/keycloak/providers/scoped-otp-ready-fixture.jar:ro']
        cls.command = command
        cls.installed_configuration = copy.deepcopy(value)
        return value


class ProtectedOperationRead(PeerReadiness):
    observation = {}

    def clean_native(self):
        OperationFixture.doClassCleanups()
        self.assertEqual([], OperationFixture.tearDown_exceptions)

    def test_committed_protected_self_reads_original_otp_with_explicit_operation_grant(self):
        # Reuse the actual five-actor/approval/create/commit/consumed/dynamic-peer proof.
        with patch('protected_peer_readiness.PeerFixture', OperationFixture):
            self.test_committed_tenant_admin_approves_own_tenant_peer_without_person_config()
        o = type(self).observation
        helper, account, human, _, _, _ = self.peer_case
        native = helper.admin('GET', '/users/' + account)
        self.assertTrue(native['enabled'])
        self.assertEqual([str(TENANT)], native['attributes']['tenantId'])
        token = helper.token('ACCOUNT_ADMIN')
        payload = token.split('.')[1]
        machine = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        audience = machine['aud']
        self.assertEqual({'userservice', 'oriso-account-lifecycle', 'oriso-otp'},
                         set([audience] if isinstance(audience, str) else audience))
        self.assertGreater(machine['exp'], time.time())
        self.assertEqual(403, call(helper.base, 'GET', '/admin/realms/' + REALM + '/users/' + account, token=token)[0])
        o['canonicalAdminThreeAudiencesAndNative403'] = True
        o['explicitSeparateSelfOperationGrantInstalled'] = (
            OperationFixture.installed_configuration['peerDelegationPolicies'][0]['id'] == POLICY
            and OperationFixture.installed_configuration['peerDelegationPolicies'][0]['accountOperations'][0]['selfOnly'] is True)
        self.assertTrue(o['explicitSeparateSelfOperationGrantInstalled'])
        target = {'accountId': account, 'tenantId': str(TENANT), 'origin': {
            'kind': 'SELF', 'workflowId': str(uuid.uuid4()), 'humanSubject': account,
            'humanIssuer': OperationFixture.native_issuer, 'humanClient': 'protected-human-web',
            'humanAuthority': 'PROTECTED_ACCOUNT_OPERATIONS_V1'}}
        helper.account_id = account
        helper.creation_input = {'account': {'username': native['username']}}
        helper.phase = lambda phase, **facts: o.update(otpReadPhase=phase, otpReadStatus=facts.get('status'))
        status, result = ScopedOtpRead.scoped_read(helper, human, target, 200, bearer=token)
        o['protectedSelfOtpReadStatus'] = status
        self.assertEqual(200, status)
        self.assertTrue({'otpSetup', 'otpSecret', 'otpSecretQrCode'} <= set(result))
        self.assertTrue(set(result) <= {'otpSetup', 'otpSecret', 'otpSecretQrCode', 'otpType'})
        self.assertFalse(result['otpSetup'])
        self.assertTrue(result['otpSecret'])
        self.assertTrue(result['otpSecretQrCode'])
        o['closedOriginalOtpSetupResultVerified'] = True
        helper.phase = lambda phase, **facts: o.update(
            maintenancePhase=phase, maintenanceCommand=facts.get('command'),
            maintenanceStatus=facts.get('status'))
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 200)
        o['protectedSelfMaintenanceReadStatus'] = status
        self.assertEqual(200, status)
        self.assertEqual(account, current['id'])
        self.assertEqual(native['username'], current['username'])
        self.assertEqual(str(TENANT), current['tenantId'])
        self.assertRegex(current['state'], r'^[a-f0-9]{64}$')
        o['closedProtectedCurrentStateVerified'] = True
        self.new_committed_platform_self(helper, o)
        seed = result['otpSecret']
        digest = hmac.new(seed.encode(), struct.pack('>Q', int(time.time()) // 30), hashlib.sha1).digest()
        offset = digest[-1] & 15
        code = str((struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)
        body = {'target': target, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                'otp': {'initialCode': code, 'secret': seed, 'email': None}}
        o['protectedAppCurrentStateAndOriginalSetupSecretVerified'] = True
        status, enrolled = ScopedOtpRead.scoped_mutation(helper, human, body, 'otp.app-setup',
                                                        'PUT', 'setup-otp', 201)
        o['protectedSelfAppSetupStatus'] = status
        self.assertEqual(201, status)
        self.assertEqual(body['operationId'], enrolled['operationId'])
        self.assertEqual(201, enrolled['status'])
        credentials = helper.admin('GET', '/users/' + account + '/credentials')
        apps = [c for c in credentials if c['type'] == 'otp']
        self.assertEqual(1, len(apps))
        self.assertEqual((201, enrolled), ScopedOtpRead.scoped_mutation(helper, human, body,
                         'otp.app-setup', 'PUT', 'setup-otp', 201))
        self.assertEqual(apps, [c for c in helper.admin('GET', '/users/' + account + '/credentials')
                               if c['type'] == 'otp'])
        o['protectedSelfAppNativeEffectAndExactRetryVerified'] = True
        self.factor_projection(helper, target, o, 'app-active', True, True)
        self.remaining_operations(helper, account, human, target, o)
        primary = helper.human(record=False)
        admin_target = copy.deepcopy(target)
        admin_target['origin'].update(kind='HUMAN_ADMIN', workflowId=str(uuid.uuid4()),
                                      humanSubject=helper.human_subject)
        from protected_terminal_operations import exercise as terminal
        from ordinary_admin_operations import exercise as ordinary
        from protected_adoption_operations import exercise as adoption
        terminal(self, helper, primary, admin_target, o)
        ordinary(self, helper, primary, (account, human), o)
        adoption(self, helper, primary, o)
        from causal_password_operations import exercise as causal
        causal(self, helper, o)
        from tenant_reassignment_operations import exercise as reassignment
        reassignment(self, helper, primary, (account, human), o)
        from profile_transition_operations import exercise as transitions
        transitions(self, helper, primary, (account, human), o)
        from import_workflow_operations import exercise as imported
        imported(self, helper, primary, (account, human), o)
        from inactivity_operations import exercise as inactivity
        inactivity(self, helper, primary, (account, human), o)
        from ordinary_adoption_operations import exercise as ordinary_adoption
        ordinary_adoption(self, helper, o)
        from ordinary_adoption_operations import timestamp_boundaries
        timestamp_boundaries(self, helper, o)
        from protected_adoption_operations import incarnation
        incarnation(self, helper, primary, o)
        from self_profile_operations import exercise as self_profile
        self_profile(self, helper, (account, human), o)
        from self_password_operations import exercise as self_password
        self_password(self, helper, (account, human), o)
        from consultant_deletion_operations import exercise as consultant_deletion
        consultant_deletion(self, helper, primary, (account, human), o)
        from profile_transition_operations import self_source_policy_boundary
        self_source_policy_boundary(self, helper, o)

    def remaining_operations(self, helper, account, human, target, observed):
        """Five finite public receiver assertions; every setup error remains an error."""
        observations = observed['remainingOperations'] = {}

        def current_state():
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 200)
            self.assertEqual(200, status)
            self.assertEqual(account, current['id'])
            self.assertRegex(current['state'], r'^[a-f0-9]{64}$')
            return current['state']

        def credentials():
            return helper.admin('GET', '/users/' + account + '/credentials')

        def mutation(operation, method, route, body, expected):
            before = credentials()
            status, result = ScopedOtpRead.scoped_mutation(helper, human, body, operation, method, route, expected)
            unchanged = before == credentials()
            observations[operation] = {'status': status, 'expected': expected,
                                       'preconditions': True, 'unchangedOnDenial': unchanged}
            if status == 403:
                self.assertTrue(unchanged)
            with self.subTest(operation=operation):
                self.assertEqual(expected, status)
                self.assertEqual(body['operationId'], result['operationId'])
                self.assertEqual(expected, result['status'])
                if operation != 'otp.email-start':
                    self.assertEqual((status, result), ScopedOtpRead.scoped_mutation(
                        helper, human, body, operation, method, route, expected))
                observations[operation]['effectAndRetryVerified'] = operation != 'otp.email-start'
            return status, result

        apps = [row for row in credentials() if row['type'] == 'otp']
        self.assertEqual(1, len(apps))
        delete = {'target': target, 'operationId': str(uuid.uuid4()),
                  'expectedState': current_state(), 'otp': None}
        delete_status, _ = mutation('otp.delete', 'DELETE', 'delete-otp', delete, 200)
        if delete_status == 200:
            self.factor_projection(helper, target, observed, 'absent', False, False)
        # Installer-only fixture isolation, never routine native power.
        for row in credentials():
            if row['type'] in {'otp', 'MAIL_OTP_CM'}:
                helper.admin('DELETE', '/users/' + account + '/credentials/' + row['id'])
        self.assertFalse(any(row['type'] in {'otp', 'MAIL_OTP_CM'} for row in credentials()))
        with patch.object(helper, 'remove_exact_mail_seed',
                          lambda credential: ScopedOtpRead.remove_exact_mail_seed(helper, credential), create=True), \
             patch.object(helper, 'addCleanup', self.addCleanup):
            credential = ScopedOtpRead.seed_pending_email_credential(helper, '937451')
        finish = {'target': target, 'operationId': str(uuid.uuid4()),
                  'expectedState': current_state(),
                  'otp': {'initialCode': '937451', 'secret': None, 'email': None}}
        finish_status, _ = mutation('otp.email-finish', 'POST', 'setup-otp-mail', finish, 201)
        if finish_status == 201:
            mail = [row for row in credentials() if row['type'] == 'MAIL_OTP_CM']
            self.assertEqual([credential], [row['id'] for row in mail])
            self.assertTrue(json.loads(mail[0]['credentialData'])['active'])
            self.factor_projection(helper, target, observed, 'mail-active', True, True)
        helper.admin('DELETE', '/users/' + account + '/credentials/' + credential)
        realm = helper.admin('GET', '')
        realm['emailTheme'] = 'oriso'
        realm['smtpServer'] = {'host': 'host.docker.internal',
                              'port': str(helper.mail.server_address[1]),
                              'from': 'otp-fixture@oriso.org', 'auth': 'false',
                              'ssl': 'false', 'starttls': 'false'}
        helper.admin('PUT', '', realm)
        self.assertEqual(realm['smtpServer'], helper.admin('GET', '')['smtpServer'])
        before_mail = len(helper.mail.messages)
        start = {'target': target, 'operationId': str(uuid.uuid4()),
                 'expectedState': current_state(), 'authorityValidUntil': int(time.time()) + 180,
                 'otp': {'initialCode': None, 'secret': None,
                         'email': 'protected-' + uuid.uuid4().hex + '@oriso.org'}}
        start_status, ready = mutation('otp.email-start', 'PUT', 'send-verification-mail', start, 202)
        if start_status == 403:
            self.assertEqual(before_mail, len(helper.mail.messages))
        if start_status == 202:
            status, sent = ScopedOtpRead.scoped_mutation(helper, human, start, 'otp.email-start',
                                                        'PUT', 'send-verification-mail', 200)
            self.assertEqual(200, status)
            self.assertEqual('SENT', sent['deliveryState'])
            self.assertEqual(ready['operationId'], sent['operationId'])
            self.assertEqual(before_mail + 1, len(helper.mail.messages))
            self.assertEqual((200, sent), ScopedOtpRead.scoped_mutation(
                helper, human, start, 'otp.email-start', 'PUT', 'send-verification-mail', 200))
            self.assertEqual(before_mail + 1, len(helper.mail.messages))
            observations['otp.email-start']['effectAndRetryVerified'] = True
            self.factor_projection(helper, target, observed, 'mail-pending', True, False)

        primary = helper.human(record=False)
        admin_target = copy.deepcopy(target)
        admin_target['origin'].update(kind='HUMAN_ADMIN', workflowId=str(uuid.uuid4()),
                                      humanSubject=helper.human_subject)
        self.assertNotEqual(account, helper.human_subject)
        primary_grant = OperationFixture.installed_configuration['bindings'][0]['accountOperations'][1]
        self.assertFalse(primary_grant['selfOnly'])
        self.assertIn(PROFILE, primary_grant['targetProfiles'])
        for operation, command in [('account.read', 'read'), ('account.profile', 'profile'), ('account.email', 'email')]:
            body = {'target': admin_target}
            if command == 'profile':
                body.update(operationId=str(uuid.uuid4()), expectedState=current_state(),
                            change={'firstName': 'Reviewed', 'lastName': 'Recipient',
                                    'email': 'managed-' + uuid.uuid4().hex + '@oriso.org'})
            if command == 'email':
                body.update(operationId=str(uuid.uuid4()), expectedState=current_state(),
                            change={'email': 'separate-' + uuid.uuid4().hex + '@oriso.org'})
            before = helper.admin('GET', '/users/' + account)
            status, result = HumanMaintenanceFixture.invoke(helper, command, body, primary, 200)
            unchanged = before == helper.admin('GET', '/users/' + account)
            observations[operation] = {'status': status, 'expected': 200,
                                       'preconditions': True, 'unchangedOnDenial': unchanged}
            if status == 403:
                self.assertTrue(unchanged)
            with self.subTest(operation=operation):
                self.assertEqual(200, status)
                if command == 'read':
                    self.assertEqual(account, result['id'])
                else:
                    self.assertEqual(body['operationId'], result['operationId'])
                    self.assertEqual((status, result), HumanMaintenanceFixture.invoke(
                        helper, command, body, primary, 200))
                    after = helper.admin('GET', '/users/' + account)
                    for field, expected in body['change'].items():
                        self.assertEqual(expected, after[field])
                observations[operation]['effectAndRetryVerified'] = True


    def factor_projection(self, helper, target, observed, name, configured, active):
        primary = helper.human(record=False)
        admin_target = copy.deepcopy(target)
        admin_target['origin'].update(kind='HUMAN_ADMIN', humanSubject=helper.human_subject)
        status, result = HumanMaintenanceFixture.invoke(helper, 'read',
            {'target': admin_target, 'include': 'TWO_FACTOR_STATUS_V1'}, primary, 200)
        entry = observed.setdefault('protectedFactor', {})[name] = {'status': status, 'expected': 200}
        with self.subTest(operation='protected.account.read.factor.' + name):
            self.assertEqual(200, status)
            self.assertEqual({'id', 'username', 'email', 'firstName', 'lastName', 'enabled', 'emailVerified',
                              'tenantId', 'preferredLanguage', 'effectiveRoles', 'passwordChangeRequired', 'state', 'twoFactor'}, set(result))
            self.assertEqual({'configured': configured, 'active': active}, result['twoFactor'])
            self.assertTrue(all(type(value) is bool for value in result['twoFactor'].values()))
            entry['exactNonsecretProjectionVerified'] = True

    def new_committed_platform_self(self, helper, observed):
        original_scope = helper.scope
        helper.scope = lambda: ProtectedInvitations.scope(helper)
        try:
            approval, attempt, scope, approved, create = helper.approved_creation()
        finally:
            helper.scope = original_scope
        self.assertEqual('PLATFORM_ADMIN', scope['protectedKind'])
        self.assertEqual([0], scope['targetTenantIds'])
        self.assertEqual(1, approved['approvalReceipt']['bindingVersion'])
        status, opened = helper.protected_machine_request('create', approval, create,
                                                        actor='ACCOUNT_CREATE', attempt=attempt)
        self.assertEqual(201, status)
        account = opened['accountId']
        self.assertFalse(helper.admin('GET', '/users/' + account)['enabled'])
        commit = {key: create[key] for key in ('approvalReceipt', 'scopeDigest',
                  'authorizationRevision', 'creationFingerprint', 'execution')}
        commit.update(accountId=account, creationProof=opened['creationProof'],
                      localCommit={'journalVersion': 1, 'outboxId': str(uuid.uuid4()), 'effectsDigest': 'a' * 64})
        status, terminal = helper.protected_machine_request('commit', approval, commit,
                                                          actor='ACCOUNT_CREATE', attempt=attempt)
        self.assertEqual(200, status)
        self.assertEqual('COMMITTED', terminal['state'])
        status, consumed = helper.protected_machine_request('status', approval, {
            'scopeDigest': approved['scopeDigest'], 'workflowId': scope['workflowId'],
            'inviteId': scope['inviteId'], 'authorizationRevision': 1, 'attemptId': attempt,
            'approvalRequestDigest': approved['approvalRequestDigest']})
        self.assertEqual(200, status)
        self.assertEqual('CONSUMED', consumed['state'])
        transition = consumed['transitionReceipt']
        verified = helper.verified_receipt(transition['receipt'], 'protected-approval-consume/v1', 24000,
            {'operation', 'state', 'approvalId', 'scopeDigest', 'boundAttemptId', 'accountId', 'terminalReceipt'})
        self.assertEqual({**verified, 'receipt': transition['receipt']}, transition)
        self.assertEqual(account, transition['accountId'])
        self.assertEqual(terminal['terminalReceipt'], transition['terminalReceipt'])
        native = helper.admin('GET', '/users/' + account)
        self.assertTrue(native['enabled'])
        self.assertEqual(['0'], native['attributes']['tenantId'])
        self.assertEqual([OperationFixture.protected_group_id],
                         [group['id'] for group in helper.admin('GET', '/users/' + account + '/groups')])
        self.assertEqual([], helper.admin('GET', '/users/' + account + '/role-mappings/realm'))
        status, token = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
            {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': native['username'],
             'password': create['account']['password'], 'scope': 'openid'}, form=True)
        self.assertEqual(200, status)
        human = token['access_token']
        payload = human.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        self.assertEqual(account, claims['sub'])
        self.assertEqual(OperationFixture.native_issuer, claims['iss'])
        self.assertEqual('protected-human-web', claims['azp'])
        self.assertEqual('0', claims['tenantId'])
        audiences = claims['aud']
        self.assertEqual({'userservice'}, set([audiences] if isinstance(audiences, str) else audiences))
        self.assertEqual({'agency-admin', 'tenant-admin'}, set(claims['realm_access']['roles']))
        self.assertFalse(claims.get('resource_access'))
        self.assertLess(claims['iat'], claims['exp'])
        self.assertGreater(claims['exp'], time.time())
        self.assertEqual({'agency-admin', 'tenant-admin'},
            {role['name'] for role in helper.admin('GET', '/users/' + account + '/role-mappings/realm/composite')})
        self.assertFalse(helper.admin('GET', '/users/' + account + '/role-mappings').get('clientMappings'))
        status, info = call(helper.base, 'GET', '/realms/' + REALM + '/protocol/openid-connect/userinfo', token=human)
        self.assertEqual(200, status)
        self.assertEqual(account, info['sub'])
        client = helper.admin('GET', '/clients?clientId=protected-human-web')
        self.assertEqual(1, len(client))
        sessions = helper.admin('GET', '/users/' + account + '/sessions')
        current = [row for row in sessions if row['id'] == claims['sid']]
        self.assertEqual(1, len(current))
        self.assertEqual('protected-human-web', current[0]['clients'][client[0]['id']])
        self.assertNotIn(account, {binding['subject'] for binding in OperationFixture.installed_configuration['bindings']})
        grant = OperationFixture.installed_configuration['bindings'][0]['accountOperations'][0]
        self.assertTrue(grant['selfOnly'])
        self.assertIn('platform-v1', grant['targetProfiles'])
        self.assertIn('otp.read', grant['operations'])
        type(helper).new_platform_account = account
        observed['newPlatformCommittedConsumedNative0AndRealSessionVerified'] = True
        observed['newPlatformExplicitRootSelfGrantWithoutPersonBindingVerified'] = True
        target = {'accountId': account, 'tenantId': '0', 'origin': {'kind': 'SELF',
                  'workflowId': str(uuid.uuid4()), 'humanSubject': account,
                  'humanIssuer': OperationFixture.native_issuer, 'humanClient': 'protected-human-web',
                  'humanAuthority': 'PROTECTED_ACCOUNT_OPERATIONS_V1'}}
        old_account, old_creation = helper.account_id, helper.creation_input
        try:
            helper.account_id = account
            helper.creation_input = {'account': {'username': native['username']}}
            status, setup = ScopedOtpRead.scoped_read(helper, human, target, 200)
            observed['newPlatformSelfOtpReadStatus'] = status
            self.assertEqual(200, status)
            self.assertFalse(setup['otpSetup'])
            self.assertTrue(setup['otpSecret'])
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 200)
            observed['newPlatformSelfMaintenanceReadStatus'] = status
            self.assertEqual(200, status)
            self.assertEqual('0', current['tenantId'])
            self.assertEqual(account, current['id'])
            observed['newPlatformSelfOriginalReadAndStateVerified'] = True
        finally:
            helper.account_id, helper.creation_input = old_account, old_creation


def classify(observed):
    required = ('actualNativeCommitAndConsumedApprovalVerified', 'actualPeerTokenIssuerClientAudienceAndGrantsVerified',
                'actualPeerUserinfoAndCurrentSessionVerified', 'sameRuntimeWithoutPerPersonBindingOrRestartVerified',
                'canonicalAdminThreeAudiencesAndNative403', 'explicitSeparateSelfOperationGrantInstalled')
    if not all(observed.get(key) is True for key in required):
        return 'INPUT_OR_FIXTURE_ERROR'
    if observed.get('protectedSelfOtpReadStatus') == 403:
        return 'GENUINE_PROTECTED_SELF_OTP_READ403_RED'
    if observed.get('protectedSelfOtpReadStatus') == 200 and observed.get('closedOriginalOtpSetupResultVerified') is True:
        if observed.get('protectedSelfMaintenanceReadStatus') == 403:
            return 'GENUINE_PROTECTED_SELF_MAINTENANCE_READ403_RED'
        if observed.get('protectedSelfMaintenanceReadStatus') == 200 and observed.get('closedProtectedCurrentStateVerified') is True:
            if observed.get('newPlatformCommittedConsumedNative0AndRealSessionVerified') is not True or observed.get('newPlatformExplicitRootSelfGrantWithoutPersonBindingVerified') is not True:
                return 'INPUT_OR_FIXTURE_ERROR'
            if observed.get('newPlatformSelfOtpReadStatus') == 403:
                return 'GENUINE_NEW_PLATFORM_SELF_OTP_READ403_RED'
            if observed.get('newPlatformSelfOriginalReadAndStateVerified') is not True:
                return 'BEHAVIOR_FAILURE'
            if observed.get('protectedAppCurrentStateAndOriginalSetupSecretVerified') is not True:
                return 'INPUT_OR_FIXTURE_ERROR'
            if observed.get('protectedSelfAppSetupStatus') == 403:
                return 'GENUINE_PROTECTED_SELF_OTP_APP403_RED'
            if observed.get('protectedSelfAppSetupStatus') == 201 and observed.get('protectedSelfAppNativeEffectAndExactRetryVerified') is True:
                remaining = observed.get('remainingOperations')
                operations = {'otp.delete': 200, 'otp.email-finish': 201, 'otp.email-start': 202,
                              'account.read': 200, 'account.profile': 200}
                if not isinstance(remaining, dict) or set(remaining) != set(operations):
                    return 'INPUT_OR_FIXTURE_ERROR'
                if any(row.get('preconditions') is not True for row in remaining.values()):
                    return 'INPUT_OR_FIXTURE_ERROR'
                if all(row.get('status') == 403 and row.get('expected') == operations[operation]
                       and row.get('unchangedOnDenial') is True
                       for operation, row in remaining.items()):
                    return 'GENUINE_PROTECTED_REMAINING_OPERATIONS403_BATCH_RED'
                if all(row.get('status') == operations[operation]
                       and row.get('effectAndRetryVerified') is True
                       for operation, row in remaining.items()):
                    return 'GREEN'
    return 'BEHAVIOR_FAILURE'
