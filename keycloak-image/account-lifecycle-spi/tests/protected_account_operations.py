"""Actual committed protected self on the original OTP route; no diagnostic endpoint."""
import base64
import copy
import hashlib
import hmac
import struct
import json
import time
import uuid
from unittest.mock import patch

from lifecycle_fixture import REALM, ACTORS, SUBJECTS, call
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
        value['bindings'][0]['accountOperations'] = [{
            'authority': 'PLATFORM', 'targetProfiles': ['platform-v1'], 'selfOnly': True,
            'operations': ['account.read', 'otp.app-setup', 'otp.delete', 'otp.email-finish', 'otp.email-start', 'otp.read'],
        }]
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
                return 'GREEN'
    return 'BEHAVIOR_FAILURE'
