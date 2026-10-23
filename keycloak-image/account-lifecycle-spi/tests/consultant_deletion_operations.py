"""Original DELETION wire: current exclusive Consultant family, owned outcome and UUID reuse."""
import base64
import copy
import hashlib
import hmac
import json
import uuid

from lifecycle_fixture import ACTORS, SUBJECTS, CONTEXT_KEY, REALM, call, canonical, mac
from maintenance_human_fixture import HumanMaintenanceFixture
from profile_transition_operations import committed_kind, human_target


def target(account, native):
    return {'accountId': account, 'tenantId': native.get('attributes', {}).get('tenantId', [None])[0],
        'origin': {'kind': 'DELETION', 'workflowId': str(uuid.uuid4()), 'humanSubject': None,
                   'humanIssuer': None, 'humanClient': None, 'humanAuthority': None}}


def deleted_receipt(test, helper, body, result):
    test.assertEqual({'operationId', 'accountId', 'result', 'receipt'}, set(result))
    test.assertEqual('DELETED', result['result']); test.assertEqual(body['operationId'], result['operationId'])
    test.assertEqual(body['target']['accountId'], result['accountId'])
    encoded, signature = result['receipt'].split('.')
    test.assertEqual(hmac.new(CONTEXT_KEY, ('maintenance-operation-receipt\n' + encoded).encode(), hashlib.sha256).hexdigest(), signature)
    expected = {'realmId': helper.realm_id, 'accountId': body['target']['accountId'], 'operationId': body['operationId'],
        'command': 'delete', 'ownerClient': ACTORS['ACCOUNT_ADMIN'][0], 'ownerSubject': SUBJECTS['ACCOUNT_ADMIN'],
        'intentDigest': mac('maintenance-intent', body), 'previousState': body['expectedState'],
        'tenantId': body['target']['tenantId'], 'originDigest': mac('maintenance-origin', body['target']['origin']), 'result': 'DELETED'}
    raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    test.assertEqual(expected, json.loads(raw)); test.assertEqual(canonical(expected), raw)


def exercise(test, helper, primary, protected, observed):
    records = observed['exclusiveConsultantDeletion'] = {}
    original_account, original_creation = helper.account_id, helper.creation_input
    try:
        for group in ['consultant-basic', 'consultant']:
            account, creation = committed_kind(test, helper, 'CONSULTANT', group)
            helper.account_id = account; helper.creation_input = creation
            native = helper.admin('GET', '/users/' + account); owned = target(account, native)
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': owned}, None, 200)
            test.assertEqual(200, status)
            test.assertEqual({'consultant'} | ({'group-chat-consultant'} if group == 'consultant' else set()), set(current['effectiveRoles']))
            body = {'target': owned, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': {}}
            status, result = HumanMaintenanceFixture.invoke(helper, 'delete', body, None, 200)
            test.assertEqual(200, status); deleted_receipt(test, helper, body, result)
            test.assertEqual(404, call(helper.base, 'GET', '/admin/realms/' + REALM + '/users/' + account, token=helper.installer)[0])
            test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, 'delete', body, None, 200))
            replacement = {'id': account, 'username': 'replacement-' + uuid.uuid4().hex, 'enabled': True,
                'email': 'replacement-' + uuid.uuid4().hex + '@oriso.org', 'firstName': 'Fresh', 'lastName': 'Incarnation',
                'attributes': {'tenantId': ['77']}}
            helper.admin('POST', '/partialImport', {'ifResourceExists': 'FAIL', 'users': [replacement]})
            fresh = helper.admin('GET', '/users/' + account); test.assertEqual(replacement['username'], fresh['username'])
            test.assertEqual((200, result), HumanMaintenanceFixture.invoke(helper, 'delete', body, None, 200))
            test.assertEqual(fresh, helper.admin('GET', '/users/' + account))
            wrong = copy.deepcopy(body); wrong['expectedState'] = '0' * 64
            conflict_status, conflict = HumanMaintenanceFixture.invoke(helper, 'delete', wrong, None, 409)
            test.assertEqual(409, conflict_status); test.assertNotIn('receipt', conflict)
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': owned}, None, 403)[0])
            records[group] = {'currentExclusiveNativeProfile': True, 'readStatus': 200, 'deleteStatus': 200,
                'originalDeleted11AndExactSavedRetry': True, 'recreatedUuidNeverDeletedOrAdopted': True}

        denied = []
        for kind, group in [('AGENCY_ADMIN', 'agency-admin'), ('CONSULTANT_AGENCY_ADMIN', 'consultant-agency-admin')]:
            account, creation = committed_kind(test, helper, kind, group)
            denied.append((kind, account, creation))
        account, creation = committed_kind(test, helper, 'CONSULTANT', 'consultant')
        helper.account_id = account; helper.creation_input = creation
        native = helper.admin('GET', '/users/' + account); administrator = human_target(helper, account, native)
        primary = helper.human(record=False)
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': administrator}, primary, 200)
        test.assertEqual(200, status)
        addition = {'target': administrator, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
            'change': {'transition': 'ADD_AGENCY_ADMIN_IDENTITY', 'group': '/human-roles/consultant-agency-admin'}}
        status, added = HumanMaintenanceFixture.invoke(helper, 'profile-transition', addition, primary, 200)
        test.assertEqual(200, status); test.assertEqual('UPDATED', added['result'])
        denied.append(('CONSULTANT_CREATION_NOW_COMBINED', account, creation))
        for label, account, creation in denied:
            helper.account_id = account; helper.creation_input = creation
            before = helper.admin('GET', '/users/' + account); owned = target(account, before)
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': owned}, None, 403)
            record = records[label] = {'readStatus': status, 'actualCommittedCurrentFullProfileAndLineage': True}
            with test.subTest(operation='deletion.exclusive-consultant.' + label + '.read'):
                test.assertEqual(403, status); test.assertNotIn('receipt', current)
            body = {'target': owned, 'operationId': str(uuid.uuid4()),
                'expectedState': current['state'] if status == 200 else '0' * 64, 'change': {}}
            delete_status, result = HumanMaintenanceFixture.invoke(helper, 'delete', body, None, 403)
            record['deleteStatus'] = delete_status
            with test.subTest(operation='deletion.exclusive-consultant.' + label + '.delete'):
                test.assertEqual(403, delete_status); test.assertNotIn('receipt', result)
            if delete_status == 200:
                deleted_receipt(test, helper, body, result)
                test.assertEqual(404, call(helper.base, 'GET', '/admin/realms/' + REALM + '/users/' + account, token=helper.installer)[0])
                record['forbiddenNativeDeletionObserved'] = True
            else:
                test.assertEqual(before, helper.admin('GET', '/users/' + account))
                record['noNativeWrite'] = True
        for label, account in [('PROTECTED', protected[0])] + list(SUBJECTS.items()):
            helper.account_id = account
            before = helper.admin('GET', '/users/' + account); owned = target(account, before)
            status, result = HumanMaintenanceFixture.invoke(helper, 'read', {'target': owned}, None, 403)
            test.assertIn(status, {400, 403}); test.assertNotIn('receipt', result)
            body = {'target': owned, 'operationId': str(uuid.uuid4()), 'expectedState': '0' * 64, 'change': {}}
            status, result = HumanMaintenanceFixture.invoke(helper, 'delete', body, None, 403)
            test.assertIn(status, {400, 403}); test.assertNotIn('receipt', result)
            test.assertEqual(before, helper.admin('GET', '/users/' + account))
            records[label] = {'currentPositiveProvenanceAbsentOrProtected': True, 'deleteStatus': status, 'noNativeWrite': True}
    finally:
        helper.account_id, helper.creation_input = original_account, original_creation
