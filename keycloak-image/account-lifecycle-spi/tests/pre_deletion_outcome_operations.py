"""Actual fresh SELF deactivate and saved-only recovery after losing its success response."""
import base64
import copy
import hashlib
import hmac
import json
import time
import uuid
from urllib.request import Request, urlopen

from lifecycle_fixture import ACTORS, CONTEXT_KEY, REALM, SUBJECTS, call, canonical, mac
from maintenance_human_fixture import HumanMaintenanceFixture
from profile_transition_operations import committed_kind
from test_maintenance import MaintenancePermissions


def updated(test, helper, body, result):
    test.assertEqual({'operationId', 'accountId', 'result', 'receipt'}, set(result))
    test.assertEqual('UPDATED', result['result'])
    encoded, signature = result['receipt'].split('.')
    test.assertEqual(hmac.new(CONTEXT_KEY, ('maintenance-operation-receipt\n' + encoded).encode(), hashlib.sha256).hexdigest(), signature)
    payload = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    expected = {'realmId': helper.realm_id, 'accountId': body['target']['accountId'],
        'operationId': body['operationId'], 'command': 'deactivate',
        'ownerClient': ACTORS['ACCOUNT_ADMIN'][0], 'ownerSubject': SUBJECTS['ACCOUNT_ADMIN'],
        'intentDigest': mac('maintenance-intent', body), 'previousState': body['expectedState'],
        'tenantId': body['target']['tenantId'], 'originDigest': mac('maintenance-origin', body['target']['origin']), 'result': 'UPDATED'}
    test.assertEqual(expected, json.loads(payload)); test.assertEqual(canonical(expected), payload)


def exercise(test, helper, observed):
    record = observed['publicPreDeletionOutcome'] = {}
    original_account, original_creation = helper.account_id, helper.creation_input
    account, creation = committed_kind(test, helper, 'ASKER', 'user')
    helper.account_id = account; helper.creation_input = creation
    try:
        native = helper.admin('GET', '/users/' + account)
        test.assertTrue(native['enabled']); test.assertGreater(native['createdTimestamp'], 0)
        client = helper.admin('GET', '/clients?clientId=protected-human-web')[0]
        original_client = copy.deepcopy(client)
        client.setdefault('attributes', {})['access.token.lifespan'] = '15'
        helper.admin('PUT', '/clients/' + client['id'], client)
        try:
            status, login = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
                {'client_id': 'protected-human-web', 'grant_type': 'password',
                 'username': native['username'], 'password': creation['account']['password'], 'scope': 'openid'}, form=True)
            test.assertEqual(200, status)
            human = login['access_token']; encoded = human.split('.')[1]
            claims = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
            test.assertEqual(account, claims['sub']); test.assertEqual({'user'}, set(claims['realm_access']['roles']))
            test.assertLessEqual(claims['exp'] - claims['iat'], 15)
        finally:
            helper.admin('PUT', '/clients/' + client['id'], original_client)
        work = str(uuid.uuid4())
        target = {'accountId': account, 'tenantId': native['attributes']['tenantId'][0], 'origin': {
            'kind': 'SELF', 'workflowId': work, 'humanSubject': account,
            'humanIssuer': type(helper).native_issuer, 'humanClient': 'protected-human-web', 'humanAuthority': None}}
        read_status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, human, 200)
        test.assertEqual(200, read_status); test.assertEqual(account, current['id'])
        body = {'target': target, 'operationId': work, 'expectedState': current['state'], 'change': {}}
        before = helper.admin('GET', '/users/' + account)
        credentials = helper.admin('GET', '/users/' + account + '/credentials')
        record.update(actualCommittedAsker=True, actualFreshPasswordLogin=True, actualSelfReadStatus=read_status,
            positiveNativeBirth=True, originalHumanExpiry=claims['exp'])

        def outcome(request=body, actor='ACCOUNT_ADMIN', proof=None):
            changes = {'operation': 'account.deactivate.outcome'}
            changes.update(proof or {})
            return MaintenancePermissions.maintenance(helper, 'deactivate/outcome', account, request,
                actor=actor, changes=changes)

        missing_status, missing = outcome()
        record['absentStatus'] = missing_status
        with test.subTest(operation='public-pre-deletion.outcome.absent-is-unknown-without-dispatch'):
            test.assertEqual(409, missing_status); test.assertNotIn('receipt', missing)
            test.assertEqual(before, helper.admin('GET', '/users/' + account))
            test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))

        helper.admin('PUT', '', {'adminEventsEnabled': True, 'adminEventsDetailsEnabled': False})
        status, result = HumanMaintenanceFixture.invoke(helper, 'deactivate', body, human, 200)
        record['freshDeactivateStatus'] = status
        with test.subTest(operation='public-pre-deletion.fresh-actual-self-disable'):
            test.assertEqual(200, status); updated(test, helper, body, result)
        if status != 200:
            return
        disabled = helper.admin('GET', '/users/' + account)
        test.assertFalse(disabled['enabled']); test.assertEqual(native['createdTimestamp'], disabled['createdTimestamp'])
        test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
        login_status, _ = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
            {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': native['username'],
             'password': creation['account']['password'], 'scope': 'openid'}, form=True)
        test.assertEqual(400, login_status)
        while time.time() <= claims['exp']:
            time.sleep(0.1)
        record['actualHumanExpiryElapsedAfterIntentionalDisable'] = True
        events = helper.admin('GET', '/admin-events')
        test.assertEqual((200, result), outcome())
        test.assertEqual(disabled, helper.admin('GET', '/users/' + account))
        test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
        test.assertEqual(events, helper.admin('GET', '/admin-events'))
        record['sameOriginalBodyAndRealReceiptAfterLostReplyAndHumanExpiry'] = True
        test.assertEqual((200, result), outcome())
        for actor in ['SETUP', 'ACCOUNT_CREATE', 'MAIL', 'RUNTIME']:
            denied_status, denied = outcome(actor=actor)
            test.assertEqual(403, denied_status); test.assertNotIn('receipt', denied)
        old_proof_status, old_proof = outcome(proof={'operation': 'account.deactivate'})
        test.assertEqual(403, old_proof_status); test.assertNotIn('receipt', old_proof)
        for field, value in [('expectedState', '0' * 64), ('operationId', str(uuid.uuid4()))]:
            wrong = copy.deepcopy(body); wrong[field] = value
            denied_status, denied = outcome(wrong)
            test.assertEqual(409, denied_status); test.assertNotIn('receipt', denied)
        record['wrongOwnerProofBodyAndAbsentOperationNeverMintReceipt'] = True

        def capsule(mode, restore=None):
            headers = {'Authorization': 'Bearer ' + helper.installer,
                'X-ORISO-Replay-Reach-Fixture': work, 'X-ORISO-Replay-Reach-Fixture-Mode': mode}
            if restore is not None:
                headers['X-ORISO-Replay-Reach-Fixture-Restore'] = restore
            request = Request(helper.base + '/admin/realms/' + REALM + '/users/' + account, headers=headers)
            with urlopen(request, timeout=30) as reply:
                test.assertEqual(200, reply.status)
                test.assertEqual(mode, reply.headers.get('X-ORISO-Replay-Reach-Fixture-Applied'))
                return reply.headers.get('X-ORISO-Replay-Reach-Fixture-Value')

        saved_capsule = capsule('OBSERVE')
        envelope = json.loads(base64.urlsafe_b64decode(saved_capsule + '=' * (-len(saved_capsule) % 4)))
        test.assertEqual({'v', 'kind', 'binding', 'mac'}, set(envelope))
        test.assertEqual('SELF_DEACTIVATION_OUTCOME_V1', envelope['kind'])
        test.assertEqual(native['createdTimestamp'], envelope['binding']['createdTimestamp'])
        test.assertEqual(claims['exp'], envelope['binding']['profile']['humanValidUntil'])
        for mode in ['BAD_MAC', 'EXTRA', 'MISSING']:
            capsule(mode)
            try:
                denied_status, denied = outcome()
                test.assertEqual(403, denied_status); test.assertNotIn('receipt', denied)
                test.assertEqual(disabled, helper.admin('GET', '/users/' + account))
            finally:
                capsule('RESTORE', saved_capsule)
            test.assertEqual((200, result), outcome())
        record['missingForeignMacAndExtraCapsuleAreClosed'] = True

        group = helper.group_id('/human-roles/user'); role = helper.admin('GET', '/roles/user')
        helper.admin('DELETE', '/groups/' + group + '/role-mappings/realm', [role])
        try:
            denied_status, denied = outcome()
            test.assertEqual(403, denied_status); test.assertNotIn('receipt', denied)
        finally:
            helper.admin('POST', '/groups/' + group + '/role-mappings/realm', [role])
        test.assertEqual((200, result), outcome())
        record['currentProfileGrantWithdrawAndRestoreCheckedWithoutHuman'] = True
        test.assertEqual(events, helper.admin('GET', '/admin-events'))

        # Same UUID/name/group/tenant is still a different native incarnation after installer replacement.
        helper.admin('DELETE', '/users/' + account)
        replacement = copy.deepcopy(disabled)
        replacement['createdTimestamp'] = native['createdTimestamp'] + 1000
        replacement.pop('access', None); replacement.pop('userProfileMetadata', None)
        replacement['credentials'] = [{'type': 'password', 'value': creation['account']['password'], 'temporary': False}]
        helper.admin('POST', '/partialImport', {'ifResourceExists': 'FAIL', 'users': [replacement]})
        helper.admin('PUT', '/users/' + account + '/groups/' + group)
        fresh = helper.admin('GET', '/users/' + account)
        test.assertNotEqual(native['createdTimestamp'], fresh['createdTimestamp'])
        denied_status, denied = outcome()
        test.assertEqual(403, denied_status); test.assertNotIn('receipt', denied)
        test.assertEqual(fresh, helper.admin('GET', '/users/' + account))
        record['recreatedSameUuidAndOtherOriginalFieldsCannotInheritOutcome'] = True
    finally:
        helper.account_id, helper.creation_input = original_account, original_creation
