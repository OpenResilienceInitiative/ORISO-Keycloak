"""One exact recipient boolean under existing current-human/profile grants; no account disclosure."""
import base64
import copy
import hashlib
import hmac
import json
import time
import uuid
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from lifecycle_fixture import ACTORS, SUBJECTS, CONTEXT_KEY, REALM, call, canonical, mac


def invoke(helper, body, human, actor='ACCOUNT_ADMIN', signed_body=None):
    now = int(time.time())
    claims = {'iss': 'userservice', 'aud': 'oriso-account-maintenance', 'purpose': 'ACCOUNT_MAINTENANCE',
              'operation': 'account.invitation-email-availability', 'method': 'POST', 'actor': actor,
              'realm': REALM, 'target': 'realm/' + helper.realm_id + '/availability/invitation-email',
              'taskClient': ACTORS[actor][0], 'taskSubject': SUBJECTS[actor],
              'payloadDigest': mac('payload', body if signed_body is None else signed_body),
              'jti': str(uuid.uuid4()), 'nonce': uuid.uuid4().hex, 'iat': now, 'exp': now + 60}
    encoded = base64.urlsafe_b64encode(canonical(claims)).decode().rstrip('=')
    signature = base64.urlsafe_b64encode(hmac.new(CONTEXT_KEY, ('proof\n' + encoded).encode(), hashlib.sha256).digest()).decode().rstrip('=')
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + helper.token(actor),
               'X-ORISO-Task-Context': encoded + '.' + signature}
    if human is not None:
        headers['X-ORISO-Human-Authorization'] = 'Bearer ' + human
    request = Request(helper.base + '/realms/' + REALM + '/oriso-account-maintenance/v1/availability/invitation-email',
                      data=canonical(body), method='POST', headers=headers)
    try:
        with urlopen(request, timeout=30) as response:
            status, raw, cache = response.status, response.read(), response.headers.get('Cache-Control', '')
    except HTTPError as error:
        status, raw, cache = error.code, error.read(), error.headers.get('Cache-Control', '')
    return status, json.loads(raw) if raw else None, cache


def exercise(test, helper, primary, peer, observed):
    records = observed['invitationEmailAvailability'] = {}
    before = helper.admin('GET', '/users?max=1000')
    # This is a new random recipient, not an existing user's returned attribute.
    unused = 'availability-' + uuid.uuid4().hex + '@example.invalid'
    body = {'email': unused, 'profile': {'family': 'ORDINARY', 'id': 'consultant-v1', 'version': 1, 'kind': 'CONSULTANT'},
            'tenantId': '11', 'tenantMode': 'EXISTING', 'origin': {'kind': 'HUMAN_ADMIN',
            'workflowId': 'invitation-email-preflight', 'humanSubject': helper.human_subject,
            'humanIssuer': type(helper).native_issuer, 'humanClient': 'protected-human-web',
            'humanAuthority': 'PROTECTED_ACCOUNT_OPERATIONS_V1'}}

    def check(label, selected, human=primary, expected=200, available=True, **kwargs):
        status, value, cache = invoke(helper, selected, human, **kwargs)
        accepted = status in expected if isinstance(expected, tuple) else status == expected
        records[label] = {'status': status, 'expectedStatus': expected, 'closedBoolean': status != 200 or value == {'available': available},
                          'noStore': 'no-store' in cache}
        test.assertTrue(accepted, 'invitation availability status: ' + label)
        test.assertTrue('no-store' in cache, 'invitation availability cache refusal: ' + label)
        if status == 200:
            test.assertTrue(value == {'available': available}, 'invitation availability discloses only boolean: ' + label)
        return status

    check('platformConsultantUnused', body)
    occupied = copy.deepcopy(body)
    occupied['email'] = helper.admin('GET', '/users/' + peer[0])['email'].lower()
    check('unrelatedExistingEmailOnlyFalse', occupied, available=False)
    for kind, profile in [('AGENCY_ADMIN', 'agency-admin-v1'), ('CONSULTANT_AGENCY_ADMIN', 'consultant-agency-admin-v1')]:
        value = copy.deepcopy(body); value['profile'].update(id=profile, kind=kind)
        check('platform' + kind, value)
    for mode in ['RESERVED_NEW', 'UNASSIGNED']:
        value = copy.deepcopy(body); value.update(tenantId=None, tenantMode=mode)
        check('platformConsultant' + mode, value)
    protected = copy.deepcopy(body)
    protected['profile'] = {'family': 'PROTECTED', 'id': 'tenant-peer-v1', 'version': 1, 'kind': 'TENANT_ADMIN'}
    protected['tenantId'] = '17'
    check('platformProtectedExisting', protected)
    # The separately reviewed reserved-new profile is selected from the installed catalogue.
    candidates = [p for p in type(helper).installed_configuration['profiles']
                  if p['id'] == 'tenant-peer-v1' and p['kind'] == 'TENANT_ADMIN' and 'RESERVED_NEW' in p['tenantModes']]
    test.assertEqual(1, len(candidates), 'one reviewed reserved-new tenant profile')
    for tenant in [None, '22']:
        value = copy.deepcopy(protected); value.update(tenantId=tenant, tenantMode='RESERVED_NEW')
        value['profile'].update(id=candidates[0]['id'], version=candidates[0]['version'])
        check('platformProtectedAuto' if tenant is None else 'platformProtectedManual', value)
    platform = copy.deepcopy(protected)
    platform['profile'].update(id='platform-v1', kind='PLATFORM_ADMIN'); platform['tenantId'] = '0'
    check('platformProtectedPlatform', platform)
    peer_body = copy.deepcopy(body); peer_body['tenantId'] = '17'; peer_body['origin']['humanSubject'] = peer[0]
    check('peerOwnConsultant', peer_body, human=peer[1])
    peer_protected = copy.deepcopy(protected); peer_protected['origin']['humanSubject'] = peer[0]
    check('peerOwnProtected', peer_protected, human=peer[1])
    foreign = copy.deepcopy(peer_body); foreign['tenantId'] = '11'
    check('peerForeignTenantDenied', foreign, human=peer[1], expected=403)
    peer_auto = copy.deepcopy(peer_protected); peer_auto.update(tenantId=None, tenantMode='RESERVED_NEW')
    check('peerAllocationDenied', peer_auto, human=peer[1], expected=403)
    restricted_id, password = type(helper).adopted_admin_cases['agency-admin']
    restricted = helper.admin('GET', '/users/' + restricted_id)
    status, tokens = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
                          {'grant_type': 'password', 'client_id': 'protected-human-web', 'username': restricted['username'], 'password': password}, form=True)
    test.assertEqual(200, status, 'existing adopted restricted human login')
    restricted_body = copy.deepcopy(body)
    restricted_body['origin'].update(humanSubject=restricted_id, humanAuthority='ORDINARY_ACCOUNT_OPERATIONS_V1')
    check('restrictedOwnConsultant', restricted_body, human=tokens['access_token'])
    restricted_foreign = copy.deepcopy(restricted_body); restricted_foreign['tenantId'] = '17'
    check('restrictedForeignTenantDenied', restricted_foreign, human=tokens['access_token'], expected=403)
    restricted_peer = copy.deepcopy(restricted_body); restricted_peer['profile'].update(id='agency-admin-v1', kind='AGENCY_ADMIN')
    check('restrictedAdminInviteDenied', restricted_peer, human=tokens['access_token'], expected=403)
    check('missingHumanDenied', body, human=None, expected=(401, 403))
    check('wrongMachineDenied', body, actor='ACCOUNT_CREATE', expected=403)
    different_human = copy.deepcopy(body); different_human['origin']['humanSubject'] = peer[0]
    check('claimedDifferentHumanDenied', different_human, expected=403)
    check('tamperedEmailProofDenied', occupied, signed_body=body, expected=403)
    extra = copy.deepcopy(body); extra['excludedAccountId'] = peer[0]
    check('nativeExclusionDenied', extra, expected=400)
    ungranted = copy.deepcopy(body)
    ungranted['profile'].update(id='combined-unacknowledged-v1', kind='CONSULTANT_AGENCY_ADMIN')
    check('existingProfileWithoutReadGrantDenied', ungranted, expected=403)
    unknown = copy.deepcopy(body); unknown['profile']['version'] = 999
    check('unreviewedProfileDenied', unknown, expected=403)
    original_roles = helper.admin('GET', '/users/' + restricted_id + '/role-mappings/realm')
    extra_role = helper.admin('GET', '/roles/tenant-admin')
    try:
        helper.admin('POST', '/users/' + restricted_id + '/role-mappings/realm', [extra_role])
        check('staleSourceRolesDenied', restricted_body, human=tokens['access_token'], expected=403)
    finally:
        helper.admin('DELETE', '/users/' + restricted_id + '/role-mappings/realm', [extra_role])
    test.assertTrue(original_roles == helper.admin('GET', '/users/' + restricted_id + '/role-mappings/realm'),
                    'restore exact original source direct roles')
    original = helper.admin('GET', '/users/' + restricted_id)
    try:
        helper.admin('PUT', '/users/' + restricted_id, {**original, 'enabled': False})
        check('disabledSourceDenied', restricted_body, human=tokens['access_token'], expected=(401, 403))
    finally:
        helper.admin('PUT', '/users/' + restricted_id, original)
    after = helper.admin('GET', '/users?max=1000')
    test.assertTrue(sorted(before, key=lambda u: u['id']) == sorted(after, key=lambda u: u['id']),
                    'email preflight preserves all native accounts')
    observed['invitationEmailNativeAccountsUnchanged'] = True
