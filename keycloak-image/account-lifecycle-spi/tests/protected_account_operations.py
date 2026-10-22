"""Actual committed protected self on the original OTP route; no diagnostic endpoint."""
import base64
import copy
import json
import time
import uuid
from unittest.mock import patch

from lifecycle_fixture import REALM, call
from protected_otp_bootstrap import BootstrapFixture
from protected_peer_readiness import PeerFixture, PeerReadiness, PROFILE, POLICY, TENANT
from test_otp_scoped import ScopedOtpRead
from maintenance_human_fixture import HumanMaintenanceFixture


class OperationFixture(BootstrapFixture, PeerFixture):
    @classmethod
    def prepare_installation(cls, helper, configuration):
        value = PeerFixture.prepare_installation.__func__(cls, helper, configuration)
        value['peerDelegationPolicies'][0]['accountOperations'] = [{
            'authority': 'TENANT_PEER', 'targetProfiles': [PROFILE], 'selfOnly': True,
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
            return 'GREEN'
    return 'BEHAVIOR_FAILURE'
