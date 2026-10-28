"""Pre-login causal assertion contracts; no invented human session or bearer."""
import base64
import copy
import hashlib
import hmac
import json
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


def exercise(test, helper, observed, adopted=False):
    records = observed['adoptedCausalPassword' if adopted else 'causalPassword'] = {}
    cases = [('ORDINARY', kind, group) for group in ['user', 'consultant', 'agency-admin', 'consultant-agency-admin']
        for kind in ['EXISTING_SETUP', 'PASSWORD_RESET']] if adopted else [
        (family, kind, None) for family in ['ORDINARY', 'PROTECTED'] for kind in ['EXISTING_SETUP', 'PASSWORD_RESET']]
    for profile_kind, kind, group in cases:
        if adopted:
            account, _ = type(helper).adopted_admin_cases['CAUSAL.' + group + '.' + kind]
            profile_id = group + '-v1'
        elif profile_kind == 'ORDINARY':
            account, creation = committed(test, helper)
            profile_id = 'consultant-v1'
        else:
            account = type(helper).adopted_account
            profile_id = type(helper).adopted_profile
        native = helper.admin('GET', '/users/' + account)
        native['requiredActions'] = ['UPDATE_PASSWORD'] if kind == 'EXISTING_SETUP' else []
        helper.admin('PUT', '/users/' + account, native)
        workflow = {'v': 1, 'kind': kind, 'claimId': str(uuid.uuid4()), 'claimVersion': 1,
                    'authorityValidUntil': int(time.time()) + 180,
                    'expectedUsername': native['username'].upper(),
                    'expectedEmailDigest': mac('maintenance-workflow-email/v1', native['email']),
                    'profileKind': profile_kind, 'profileId': profile_id, 'profileVersion': 1}
        target = {'accountId': account, 'tenantId': native['attributes']['tenantId'][0], 'origin': {'kind': 'PASSWORD_RESET',
                  'workflowId': str(uuid.uuid4()), 'humanSubject': None, 'humanIssuer': None,
                  'humanClient': None, 'humanAuthority': None}}
        read = {'target': target, 'workflow': workflow}
        status, current = invoke(helper, account, 'account.password-reset.read', read)
        label = profile_kind + '.' + kind + ('.' + group if adopted else '')
        records[label] = {'readStatus': status, 'preconditions': True, 'withoutHumanHeader': True, 'uppercaseOriginalUsername': workflow['expectedUsername'] != native['username']}
        with test.subTest(operation='causal.' + label + '.read'):
            test.assertEqual(200, status); test.assertEqual(account, current['id'])
            test.assertEqual(kind == 'EXISTING_SETUP', current['passwordChangeRequired'])
        if status != 200:
            continue
        for selector, changed_value, expected in [('expectedUsername', 'foreign-username', 403),
                ('expectedEmailDigest', 'a' * 64, 403), ('profileId', 'foreign-profile', 403),
                ('authorityValidUntil', int(time.time()) - 1, 400)]:
            wrong = copy.deepcopy(read); wrong['workflow'][selector] = changed_value
            test.assertEqual(expected, invoke(helper, account, 'account.password-reset.read', wrong)[0])
        extra = copy.deepcopy(read); extra['workflow']['humanAuthority'] = 'PLATFORM'
        test.assertEqual(400, invoke(helper, account, 'account.password-reset.read', extra)[0])
        body = {**read, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                'change': {'password': 'Native-causal-fixture-\n\t ' + uuid.uuid4().hex, 'temporary': False}}
        before_events = {event['id'] for event in helper.admin('GET', '/admin-events?max=100')
            if event.get('resourcePath') == 'accounts/' + account}
        status, result = invoke(helper, account, 'account.password-reset', body)
        records[label]['mutationStatus'] = status
        with test.subTest(operation='causal.' + label + '.mutation'):
            test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
            test.assertEqual((status, result), invoke(helper, account, 'account.password-reset', body))
            test.assertNotIn('UPDATE_PASSWORD', helper.admin('GET', '/users/' + account).get('requiredActions', []))
            login_status, login = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
                {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': native['username'],
                 'password': body['change']['password'], 'scope': 'openid'}, form=True)
            test.assertEqual(200, login_status)
            info_status, info = call(helper.base, 'GET', '/realms/' + REALM + '/protocol/openid-connect/userinfo',
                                     token=login['access_token'])
            test.assertEqual(200, info_status); test.assertEqual(account, info['sub'])
            changed = copy.deepcopy(body); changed['change']['password'] = 'Changed-flight-payload-937451'
            test.assertEqual(409, invoke(helper, account, 'account.password-reset', changed)[0])
            test.assertEqual((status, result), invoke(helper, account, 'account.password-reset.read', read))
            another = copy.deepcopy(body); another['operationId'] = str(uuid.uuid4())
            conflict_status, conflict = invoke(helper, account, 'account.password-reset', another)
            test.assertEqual(409, conflict_status); test.assertNotIn('receipt', conflict)
            changed_workflow = copy.deepcopy(read); changed_workflow['workflow']['expectedUsername'] += '-changed'
            conflict_status, conflict = invoke(helper, account, 'account.password-reset.read', changed_workflow)
            test.assertEqual(409, conflict_status); test.assertNotIn('receipt', conflict)
            records[label]['effectAndExactRetryVerified'] = True
            records[label]['opaqueChosenPasswordExactNativeLogin'] = True
            records[label]['exactSavedReadAndClaimReservationVerified'] = True
        if status == 200:
            added = [event for event in helper.admin('GET', '/admin-events?max=100')
                if event.get('resourcePath') == 'accounts/' + account and event['id'] not in before_events]
            with test.subTest(operation='causal.' + label + '.canonical-admin-event'):
                test.assertEqual(1, len(added))
                test.assertEqual('UPDATE', added[0]['operationType']); test.assertEqual('USER', added[0]['resourceType'])
                test.assertEqual(SUBJECTS['ACCOUNT_ADMIN'], added[0]['authDetails']['userId'])
                test.assertEqual(ACTORS['ACCOUNT_ADMIN'][0], added[0]['authDetails']['clientId'])
                test.assertEqual(helper.realm_id, added[0]['authDetails']['realmId'])
                test.assertFalse(added[0].get('representation'))
                records[label]['canonicalAdminEventWithoutSecretsOrReplayDuplicate'] = True
    if not adopted and all(value.get('effectAndExactRetryVerified') for value in records.values()):
        terminal_and_expired_history(test, helper, observed)


def terminal_and_expired_history(test, helper, observed):
    account, _ = committed(test, helper)
    native = helper.admin('GET', '/users/' + account)
    def selection(deadline):
        target = {'accountId': account, 'tenantId': native['attributes']['tenantId'][0], 'origin': {
            'kind': 'PASSWORD_RESET', 'workflowId': str(uuid.uuid4()), 'humanSubject': None,
            'humanIssuer': None, 'humanClient': None, 'humanAuthority': None}}
        workflow = {'v': 1, 'kind': 'PASSWORD_RESET', 'claimId': str(uuid.uuid4()), 'claimVersion': 1,
            'authorityValidUntil': deadline, 'expectedUsername': native['username'].upper(),
            'expectedEmailDigest': mac('maintenance-workflow-email/v1', native['email']),
            'profileKind': 'ORDINARY', 'profileId': 'consultant-v1', 'profileVersion': 1}
        return {'target': target, 'workflow': workflow}
    read = selection(int(time.time()) + 120)
    status, current = invoke(helper, account, 'account.password-reset.read', read)
    test.assertEqual(200, status)
    body = {**copy.deepcopy(read), 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
            'change': {'password': 'Too-short-1', 'temporary': False}}
    realm = helper.admin('GET', '')
    helper.admin('PUT', '', {'passwordPolicy': 'length(100)'})
    try:
        status, terminal = invoke(helper, account, 'account.password-reset', body)
        test.assertEqual(400, status); test.assertEqual('NO_EFFECT', terminal['result'])
        test.assertEqual({'operationId', 'accountId', 'result', 'status', 'receipt'}, set(terminal))
        encoded, signature = terminal['receipt'].split('.')
        test.assertEqual(hmac.new(CONTEXT_KEY, ('maintenance-no-effect-receipt/v1\n' + encoded).encode(), hashlib.sha256).hexdigest(), signature)
        payload = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        test.assertEqual(12, len(payload)); test.assertEqual(400, payload['status']); test.assertEqual('password-reset', payload['command'])
        test.assertEqual(mac('maintenance-intent', body), payload['intentDigest'])
    finally:
        helper.admin('PUT', '', {'passwordPolicy': realm.get('passwordPolicy', '')})
    test.assertEqual((status, terminal), invoke(helper, account, 'account.password-reset', body))
    test.assertEqual((status, terminal), invoke(helper, account, 'account.password-reset.read', read))
    read = selection(int(time.time()) + 5)
    status, current = invoke(helper, account, 'account.password-reset.read', read)
    test.assertEqual(200, status)
    body = {**copy.deepcopy(read), 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
            'change': {'password': 'Historical-causal-' + uuid.uuid4().hex, 'temporary': False}}
    status, result = invoke(helper, account, 'account.password-reset', body)
    test.assertEqual(200, status)
    time.sleep(max(0, read['workflow']['authorityValidUntil'] - int(time.time()) + 1))
    changed = copy.deepcopy(native); changed['firstName'] = 'Concurrent-native-profile'
    helper.admin('PUT', '/users/' + account, changed)
    before = helper.admin('GET', '/users/' + account)
    test.assertEqual((status, result), invoke(helper, account, 'account.password-reset.read', read))
    test.assertEqual((status, result), invoke(helper, account, 'account.password-reset', body))
    test.assertEqual(before, helper.admin('GET', '/users/' + account))
    missing = copy.deepcopy(read); missing['workflow']['claimId'] = str(uuid.uuid4())
    missing_status, missing_reply = invoke(helper, account, 'account.password-reset.read', missing)
    test.assertEqual(400, missing_status); test.assertNotIn('receipt', missing_reply)
    observed['causalTerminalHistory'] = {'policy400SignedAndFenced': True,
        'savedReadAndMutationAfterExpiryBeforeMutableState': True, 'expiredAbsentDenied': True}
