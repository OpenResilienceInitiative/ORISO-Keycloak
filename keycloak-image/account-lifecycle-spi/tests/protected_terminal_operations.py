"""A definite authenticated pre-write rejection permanently fences one original intent."""
import base64
import copy
import hashlib
import hmac
import json
import uuid

from lifecycle_fixture import CONTEXT_KEY, canonical, mac
from maintenance_human_fixture import HumanMaintenanceFixture


def exercise(test, helper, primary, target, observed):
    records = observed['terminalNoEffect'] = {}
    account = helper.account_id
    for refusal in [409, 403]:
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 200)
        test.assertEqual(200, status)
        original = helper.admin('GET', '/users/' + account)
        body = {'target': copy.deepcopy(target), 'operationId': str(uuid.uuid4()),
                'expectedState': current['state'],
                'change': {'firstName': 'NoEffect', 'lastName': 'Frozen', 'email': original['email']}}
        drift = copy.deepcopy(original)
        if refusal == 409:
            drift['firstName'] = 'Concurrent-' + uuid.uuid4().hex
        else:
            drift['enabled'] = False
        helper.admin('PUT', '/users/' + account, drift)
        try:
            status, terminal = HumanMaintenanceFixture.invoke(helper, 'profile', body, primary, refusal)
            unchanged = helper.admin('GET', '/users/' + account) == drift
            test.assertTrue(unchanged)
            records[str(refusal)] = {'status': status, 'preconditions': True, 'unchanged': unchanged}
            with test.subTest(operation='account.profile.no-effect.' + str(refusal)):
                test.assertEqual(refusal, status)
                test.assertEqual({'operationId', 'accountId', 'result', 'status', 'receipt'}, set(terminal))
                test.assertEqual('NO_EFFECT', terminal['result']); test.assertEqual(refusal, terminal['status'])
                test.assertEqual(body['operationId'], terminal['operationId']); test.assertEqual(account, terminal['accountId'])
                encoded, signature = terminal['receipt'].split('.')
                expected_signature = hmac.new(CONTEXT_KEY,
                    ('maintenance-no-effect-receipt/v1\n' + encoded).encode(), hashlib.sha256).hexdigest()
                test.assertEqual(expected_signature, signature)
                payload = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
                test.assertEqual({'realmId', 'accountId', 'operationId', 'command', 'ownerClient', 'ownerSubject',
                                  'intentDigest', 'previousState', 'tenantId', 'originDigest', 'result', 'status'}, set(payload))
                test.assertEqual(canonical(payload), base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
                test.assertEqual('profile', payload['command']); test.assertEqual('NO_EFFECT', payload['result'])
                test.assertEqual(refusal, payload['status']); test.assertEqual(mac('maintenance-intent', body), payload['intentDigest'])
                test.assertEqual(mac('maintenance-origin', target['origin']), payload['originDigest'])
                test.assertEqual(body['expectedState'], payload['previousState']); test.assertEqual(target['tenantId'], payload['tenantId'])
                test.assertEqual(helper.realm_id, payload['realmId']); test.assertEqual(account, payload['accountId'])
                # Restore the exact old CAS. A durable no-effect outcome can never apply now.
                helper.admin('PUT', '/users/' + account, original)
                test.assertEqual((status, terminal), HumanMaintenanceFixture.invoke(helper, 'profile', body, primary, refusal))
                test.assertEqual(original, helper.admin('GET', '/users/' + account))
                changed = copy.deepcopy(body); changed['change']['firstName'] = 'Foreign'
                conflict_status, conflict = HumanMaintenanceFixture.invoke(helper, 'profile', changed, primary, 409)
                test.assertEqual(409, conflict_status); test.assertNotIn('receipt', conflict)
                records[str(refusal)]['signedExactTerminalAndRestoredCasFenceVerified'] = True
        finally:
            helper.admin('PUT', '/users/' + account, original)
