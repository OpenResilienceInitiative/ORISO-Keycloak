"""Pre-login causal assertion contracts; no invented human session or bearer."""
import base64
import copy
import hashlib
import hmac
import time
import uuid

from lifecycle_fixture import ACTORS, SUBJECTS, CONTEXT_KEY, REALM, canonical, call, mac
from ordinary_admin_operations import committed


def invoke(helper, account, operation, body):
    now = int(time.time())
    claims = {'iss': 'userservice', 'aud': 'oriso-account-maintenance',
              'purpose': 'ACCOUNT_MAINTENANCE', 'operation': operation, 'method': 'POST',
              'actor': 'ACCOUNT_ADMIN', 'realm': REALM,
              'target': 'realm/' + helper.realm_id + '/account/' + account,
              'taskClient': ACTORS['ACCOUNT_ADMIN'][0], 'taskSubject': SUBJECTS['ACCOUNT_ADMIN'],
              'payloadDigest': mac('payload', body), 'jti': str(uuid.uuid4()),
              'nonce': uuid.uuid4().hex, 'iat': now, 'exp': now + 60}
    encoded = base64.urlsafe_b64encode(canonical(claims)).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(hmac.new(CONTEXT_KEY,
        ('proof\n' + encoded).encode(), hashlib.sha256).digest()).decode().rstrip('=')
    suffix = 'password-reset/read' if operation == 'account.password-reset.read' else 'password-reset'
    return call(helper.base, 'POST', '/realms/' + REALM + '/oriso-account-maintenance/v1/accounts/'
                + account + '/' + suffix, body, helper.token('ACCOUNT_ADMIN'), proof=encoded + '.' + signature)


def exercise(test, helper, observed):
    records = observed['causalPassword'] = {}
    for kind in ['EXISTING_SETUP', 'PASSWORD_RESET']:
        account, creation = committed(test, helper)
        native = helper.admin('GET', '/users/' + account)
        if kind == 'EXISTING_SETUP':
            native['requiredActions'] = ['UPDATE_PASSWORD']; helper.admin('PUT', '/users/' + account, native)
        workflow = {'v': 1, 'kind': kind, 'claimId': str(uuid.uuid4()), 'claimVersion': 1,
                    'authorityValidUntil': int(time.time()) + 180,
                    'expectedUsername': native['username'],
                    'expectedEmailDigest': mac('maintenance-workflow-email/v1', native['email']),
                    'profileKind': 'ORDINARY', 'profileId': 'consultant-v1', 'profileVersion': 1}
        target = {'accountId': account, 'tenantId': '11', 'origin': {'kind': 'PASSWORD_RESET',
                  'workflowId': str(uuid.uuid4()), 'humanSubject': None, 'humanIssuer': None,
                  'humanClient': None, 'humanAuthority': None}}
        read = {'target': target, 'workflow': workflow}
        status, current = invoke(helper, account, 'account.password-reset.read', read)
        records[kind] = {'readStatus': status, 'preconditions': True, 'withoutHumanHeader': True}
        with test.subTest(operation='causal.' + kind + '.read'):
            test.assertEqual(200, status); test.assertEqual(account, current['id'])
            test.assertEqual(kind == 'EXISTING_SETUP', current['passwordChangeRequired'])
        if status != 200:
            continue
        body = {**read, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                'change': {'password': 'Native-causal-fixture-new-7391', 'temporary': False}}
        status, result = invoke(helper, account, 'account.password-reset', body)
        records[kind]['mutationStatus'] = status
        with test.subTest(operation='causal.' + kind + '.mutation'):
            test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
            test.assertEqual((status, result), invoke(helper, account, 'account.password-reset', body))
            test.assertNotIn('UPDATE_PASSWORD', helper.admin('GET', '/users/' + account).get('requiredActions', []))
            changed = copy.deepcopy(body); changed['change']['password'] = 'Changed-flight-payload-937451'
            test.assertEqual(409, invoke(helper, account, 'account.password-reset', changed)[0])
            records[kind]['effectAndExactRetryVerified'] = True
