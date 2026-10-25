"""Finite ordinary target operations through the original authenticated maintenance route."""
import base64
import copy
import json
import uuid

from lifecycle_fixture import ACTORS, SUBJECTS, REALM, IMAGE, LifecycleFixture, call
from maintenance_human_fixture import HumanMaintenanceFixture
from test_maintenance import MaintenancePermissions

OPERATIONS = ['account.deactivate', 'account.email', 'account.ordinary-profile',
              'account.profile', 'account.reactivate', 'account.read', 'account.profile-transition']


def install_policy(cls, helper, protected):
    parent = helper.group_id('/human-roles')
    helper.admin('POST', '/groups/' + parent + '/children', {'name': 'consultant-basic'})
    helper.admin('POST', '/groups/' + helper.group_id('/human-roles/consultant-basic') + '/role-mappings/realm',
                 [helper.admin('GET', '/roles/consultant')])
    profiles = []
    for group, roles in [('consultant', ['consultant', 'group-chat-consultant']),
                         ('consultant-basic', ['consultant']), ('user', ['user']),
                         ('agency-admin', ['restricted-agency-admin', 'user-admin']),
                         ('consultant-agency-admin', ['consultant', 'group-chat-consultant', 'restricted-agency-admin', 'user-admin'])]:
        profiles.append({'id': group + '-v1', 'version': 1,
                         'groupId': helper.group_id('/human-roles/' + group),
                         'groupPath': '/human-roles/' + group,
                         'groupParentId': helper.group_id('/human-roles'),
                         'realmRoles': roles, 'clientRoles': {}, 'allowUnassignedTenant': False,
                         'selfOperations': (['account.read'] if group == 'consultant-basic' else ['account.password', 'account.read']) + (['account.email', 'account.locale', 'account.profile'] if group in {'consultant', 'consultant-agency-admin'} else ['account.email', 'account.locale'] if group == 'user' else ['account.profile'] if group == 'consultant-basic' else ['account.email'] if group == 'agency-admin' else [])})
    # Closed input seam: only the reviewed asker profile may request SELF deactivation.
    next(profile for profile in profiles if profile['id'] == 'user-v1')['selfOperations'].append('account.deactivate')
    client = helper.admin('GET', '/clients?clientId=protected-human-web')[0]['id']
    reviewed_roles = sorted({role for profile in profiles for role in profile['realmRoles']})
    helper.admin('POST', '/clients/' + client + '/scope-mappings/realm',
        [helper.admin('GET', '/roles/' + role) for role in reviewed_roles])
    native = {key: copy.deepcopy(protected[key]) for key in
              ['realmId', 'issuer', 'technicalSubjects', 'technicalGroupIds', 'technicalRoles']}
    native.update(clientIds=['protected-human-web'], audienceSets=[['userservice']])
    config = {'version': 1, 'native': native, 'ordinaryProfiles': profiles,
              'adminOperations': [{'authority': authority, 'selfOnly': False,
                                   'targetProfiles': ['consultant-v1', 'consultant-basic-v1', 'user-v1', 'agency-admin-v1', 'consultant-agency-admin-v1'],
                                   'operations': OPERATIONS} for authority in ['PLATFORM', 'TENANT_PEER']]}
    username = 'adopted-ordinary-' + uuid.uuid4().hex
    helper.admin('POST', '/users', {'username': username, 'enabled': True, 'email': username + '@oriso.org',
        'firstName': 'Legacy', 'lastName': 'Asker', 'attributes': {'tenantId': ['11']}})
    users = helper.admin('GET', '/users?username=' + username + '&exact=true'); helper.assertEqual(1, len(users))
    account = users[0]['id']; defaults = helper.admin('GET', '/users/' + account + '/role-mappings/realm')
    if defaults: helper.admin('DELETE', '/users/' + account + '/role-mappings/realm', defaults)
    helper.admin('PUT', '/users/' + account + '/groups/' + helper.group_id('/human-roles/user'))
    config['adoptedAccounts'] = [{'accountId': account, 'ordinaryProfileId': 'user-v1', 'profileVersion': 1}]
    cls.ordinary_adopted_account = account
    for boundary, timestamp in [('null', None), ('zero', 0)]:
        username = 'adopted-' + boundary + '-' + uuid.uuid4().hex
        representation = {'username': username, 'enabled': True, 'email': username + '@oriso.org',
            'firstName': 'Timestamp', 'lastName': 'Boundary', 'attributes': {'tenantId': ['11']}}
        if timestamp is not None: representation['createdTimestamp'] = timestamp
        helper.admin('POST', '/users', representation)
        controls = helper.admin('GET', '/users?username=' + username + '&exact=true'); helper.assertEqual(1, len(controls))
        control = controls[0]['id']; defaults = helper.admin('GET', '/users/' + control + '/role-mappings/realm')
        if defaults: helper.admin('DELETE', '/users/' + control + '/role-mappings/realm', defaults)
        helper.admin('PUT', '/users/' + control + '/groups/' + helper.group_id('/human-roles/user'))
        config['adoptedAccounts'].append({'accountId': control, 'ordinaryProfileId': 'user-v1', 'profileVersion': 1})
        setattr(cls, 'ordinary_' + boundary + '_adopted_account', control)

    for label, profile in [('inactivity-incarnation', 'user'), ('inactivity-ungranted', 'consultant-basic')]:
        username = 'adopted-' + label + '-' + uuid.uuid4().hex
        helper.admin('POST', '/users', {'username': username, 'enabled': True, 'email': username + '@oriso.org',
            'firstName': 'Workflow', 'lastName': 'Boundary', 'attributes': {'tenantId': ['11']}})
        controls = helper.admin('GET', '/users?username=' + username + '&exact=true'); helper.assertEqual(1, len(controls))
        control = controls[0]['id']; defaults = helper.admin('GET', '/users/' + control + '/role-mappings/realm')
        if defaults: helper.admin('DELETE', '/users/' + control + '/role-mappings/realm', defaults)
        helper.admin('PUT', '/users/' + control + '/groups/' + helper.group_id('/human-roles/' + profile))
        config['adoptedAccounts'].append({'accountId': control, 'ordinaryProfileId': profile + '-v1', 'profileVersion': 1})
        setattr(cls, 'ordinary_' + label.replace('-', '_') + '_account', control)

    config['workflowOperations'] = [{'kind': 'INACTIVITY', 'targetProfiles': ['consultant-v1', 'user-v1'],
        'operations': ['account.deactivate', 'account.reactivate', 'account.read']},
        {'kind': 'IMPORT', 'targetProfiles': ['consultant-v1', 'consultant-agency-admin-v1'],
         'operations': ['account.read', 'account.ordinary-profile']}]
    from adopted_self_operations import install as install_adopted_self
    install_adopted_self(cls, helper, config)
    from adopted_admin_operations import install as install_adopted_admin
    install_adopted_admin(cls, helper, config)
    command = cls.command.copy()
    for index, argument in enumerate(command):
        if argument.startswith('ORISO_ACCOUNT_LIFECYCLE_GROUPS='):
            reviewed_groups = json.loads(argument.split('=', 1)[1])
            reviewed_groups.update({profile['groupPath']: profile['realmRoles'] for profile in profiles})
            command[index] = 'ORISO_ACCOUNT_LIFECYCLE_GROUPS=' + json.dumps(reviewed_groups, separators=(',', ':'))
    index = command.index(IMAGE)
    command[index:index] = ['-e', 'ORISO_ACCOUNT_MAINTENANCE_CONFIG=' + json.dumps(config, separators=(',', ':'))]
    cls.command = command
    cls.ordinary_installed_configuration = copy.deepcopy(config)


def exercise(test, helper, primary, peer, observed):
    """A separate command gets a separate subassertion; no fixture/setup exception is RED."""
    records = observed['ordinaryOperations'] = {}
    histories = {}
    account, creation = committed(test, helper)
    target = {'accountId': account, 'tenantId': '11', 'origin': {
        'kind': 'HUMAN_ADMIN', 'workflowId': str(uuid.uuid4()), 'humanSubject': helper.human_subject,
        'humanIssuer': type(helper).native_issuer, 'humanClient': 'protected-human-web',
        'humanAuthority': 'PROTECTED_ACCOUNT_OPERATIONS_V1'}}
    old_account, old_create = helper.account_id, helper.creation_input
    helper.account_id, helper.creation_input = account, creation
    try:
        bearer = helper.token('ACCOUNT_ADMIN')
        test.assertEqual(403, call(helper.base, 'GET', '/admin/realms/' + REALM + '/users/' + account, token=bearer)[0])
        test.assertTrue(helper.admin('GET', '/users/' + account)['enabled'])
        test.assertEqual(['11'], helper.admin('GET', '/users/' + account)['attributes']['tenantId'])

        def invoke(command, change=None):
            body = {'target': target}
            if command != 'read':
                # This independent checked deletion read supplies fixture CAS only while the
                # original profile remains unchanged; it confers no human admin authority.
                status, current = HumanMaintenanceFixture.invoke(helper, 'read', body, primary, 200)
                if status == 403:
                    deletion = MaintenancePermissions.target(account, creation)
                    status, current = MaintenancePermissions.maintenance(helper, 'read', account, {'target': deletion})
                test.assertEqual(200, status)
                body.update(operationId=str(uuid.uuid4()), expectedState=current['state'], change=change)
            before = helper.admin('GET', '/users/' + account)
            status, result = HumanMaintenanceFixture.invoke(helper, command, body, primary, 200)
            unchanged = before == helper.admin('GET', '/users/' + account)
            records['account.' + command] = {'status': status, 'expected': 200,
                'preconditions': True, 'unchangedOnDenial': unchanged}
            if status == 403:
                test.assertTrue(unchanged)
            with test.subTest(operation='ordinary.account.' + command):
                test.assertEqual(200, status)
                if command == 'read':
                    test.assertEqual(account, result['id'])
                else:
                    test.assertEqual('UPDATED', result['result'])
                    histories[command] = (copy.deepcopy(body), copy.deepcopy(result))
                    test.assertEqual(body['operationId'], result['operationId'])
                    test.assertEqual((status, result), HumanMaintenanceFixture.invoke(helper, command, body, primary, 200))
                    fresh = helper.admin('GET', '/users/' + account)
                    if command in {'profile', 'email'}:
                        for field, expected in change.items():
                            test.assertEqual(expected, fresh.get(field))
                    elif command == 'ordinary-profile':
                        test.assertEqual({helper.group_id(change['group'])},
                                         {row['id'] for row in helper.admin('GET', '/users/' + account + '/groups')})
                        for field, expected in change.get('profile', {}).items():
                            test.assertEqual(expected, fresh.get(field))
                    elif command in {'deactivate', 'reactivate'}:
                        test.assertEqual(command == 'reactivate', fresh['enabled'])
                records['account.' + command]['effectAndRetryVerified'] = True
            return status

        invoke('read')
        status, projection = HumanMaintenanceFixture.invoke(helper, 'read',
            {'target': target, 'include': 'TWO_FACTOR_STATUS_V1'}, primary, 200)
        records['account.read.two-factor'] = {'status': status, 'expected': 200, 'preconditions': True}
        with test.subTest(operation='ordinary.account.read.two-factor'):
            test.assertEqual(200, status)
            test.assertEqual({'configured': False, 'active': False}, projection['twoFactor'])
            test.assertEqual({'id', 'username', 'email', 'firstName', 'lastName', 'enabled', 'emailVerified',
                              'tenantId', 'preferredLanguage', 'effectiveRoles', 'passwordChangeRequired',
                              'state', 'twoFactor'}, set(projection))
        for invalid in [None, True, 1, 'OTP_SECRET', {'twoFactor': True}]:
            invalid_status, _ = HumanMaintenanceFixture.invoke(helper, 'read',
                {'target': target, 'include': invalid}, primary, 400)
            test.assertEqual(400, invalid_status)
        invoke('profile', {'firstName': 'Ordinary', 'lastName': 'Managed', 'email': creation['account']['email']})
        invoke('email', {'email': 'ordinary-' + uuid.uuid4().hex + '@oriso.org'})
        invoke('ordinary-profile', {'group': '/human-roles/consultant-basic',
                                    'profile': {'firstName': 'Combined', 'lastName': 'Atomic',
                                                'email': helper.admin('GET', '/users/' + account)['email']}})
        inactive = invoke('deactivate', {})
        if inactive == 403:
            fresh = helper.admin('GET', '/users/' + account); fresh['enabled'] = False
            helper.admin('PUT', '/users/' + account, fresh)
        native = helper.admin('GET', '/users/' + account)
        invoke('reactivate', {'expectedUsername': native['username'], 'expectedEmail': native['email'],
                              'password': 'Finite-reactivation-fixture-937451'})
        # An actual independently committed peer from tenant17 cannot touch tenant11.
        cross = copy.deepcopy(target); cross['origin']['humanSubject'] = peer[0]
        status, _ = HumanMaintenanceFixture.invoke(helper, 'read', {'target': cross}, peer[1], 403)
        test.assertEqual(403, status)
        observed['ordinaryCrossTenantPeerDenied'] = True
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': target}, primary, 200)
        test.assertEqual(200, status)
        refused = {'target': copy.deepcopy(target), 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
            'change': {'expectedUsername': native['username'], 'expectedEmail': native['email'], 'password': 'short'}}
        realm = helper.admin('GET', ''); helper.admin('PUT', '', {'passwordPolicy': 'length(100)'})
        try:
            status, terminal = HumanMaintenanceFixture.invoke(helper, 'reactivate', refused, primary, 400)
            records['reactivatePolicy400'] = {'status': status, 'preconditions': True}
            with test.subTest(operation='ordinary.reactivate.policy400'):
                test.assertEqual(400, status); test.assertEqual('NO_EFFECT', terminal.get('result'))
                test.assertEqual({'operationId', 'accountId', 'result', 'status', 'receipt'}, set(terminal))
                records['reactivatePolicy400']['signedPrewriteRefusal'] = True
        finally:
            helper.admin('PUT', '', {'passwordPolicy': realm.get('passwordPolicy', '')})
        if terminal.get('result') == 'NO_EFFECT':
            test.assertEqual((status, terminal), HumanMaintenanceFixture.invoke(helper, 'reactivate', refused, primary, 400))
        current_native = helper.admin('GET', '/users/' + account)
        login_status, login = call(helper.base, 'POST', '/realms/' + REALM + '/protocol/openid-connect/token',
            {'client_id': 'protected-human-web', 'grant_type': 'password', 'username': current_native['username'],
             'password': 'Finite-reactivation-fixture-937451', 'scope': 'openid'}, form=True)
        test.assertEqual(200, login_status)
        encoded = login['access_token'].split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        test.assertEqual({'consultant'}, set(claims.get('realm_access', {}).get('roles', [])))
        records['postRoleSelfTokenExactCurrentRoles'] = True
        self_target = copy.deepcopy(target); self_target['origin'].update(kind='SELF', humanSubject=account, humanAuthority=None)
        status, self_current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': self_target}, login['access_token'], 200)
        records['postRoleSelf'] = {'status': status, 'preconditions': True}
        with test.subTest(operation='ordinary.post-role.self-read'):
            test.assertEqual(200, status); test.assertEqual(['consultant'], self_current['effectiveRoles'])
            records['postRoleSelf']['currentLineageVerified'] = True
        from maintenance_replay_reach_operations import exercise as replay_reach
        replay_reach(test, helper, primary, histories, observed)
        deletion = MaintenancePermissions.target(account, creation)
        status, delete_current = MaintenancePermissions.maintenance(helper, 'read', account, {'target': deletion})
        records['postRoleDeletion'] = {'readStatus': status, 'preconditions': True}
        with test.subTest(operation='ordinary.post-role.owned-job-read'):
            test.assertEqual(200, status); test.assertEqual(['consultant'], delete_current['effectiveRoles'])
        if status == 200:
            delete = {'target': deletion, 'operationId': str(uuid.uuid4()), 'expectedState': delete_current['state'], 'change': {}}
            status, deleted = MaintenancePermissions.maintenance(helper, 'delete', account, delete)
            with test.subTest(operation='ordinary.post-role.owned-job-delete'):
                test.assertEqual(200, status); test.assertEqual('DELETED', deleted['result'])
                test.assertEqual((status, deleted), MaintenancePermissions.maintenance(helper, 'delete', account, delete))
                records['postRoleDeletion']['actualDeleteAndExactRetryVerified'] = True
                from maintenance_replay_reach_operations import deleted_history
                deleted_history(test, helper, primary, histories, observed)

    finally:
        helper.account_id, helper.creation_input = old_account, old_create


def committed(test, helper):
    attempt = str(uuid.uuid4())
    creation = LifecycleFixture.creation(helper)
    status, opened = LifecycleFixture.request(helper, 'create', attempt, creation)
    test.assertEqual(201, status)
    status, terminal = LifecycleFixture.request(helper, 'commit', attempt, LifecycleFixture.finish(helper, creation, opened))
    test.assertEqual(200, status)
    test.assertEqual('COMMITTED', terminal['state'])
    return opened['accountId'], creation
