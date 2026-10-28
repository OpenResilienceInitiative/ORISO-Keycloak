"""Actual identity-preserving native removal in ordinary, tenant and platform families."""
import copy
import uuid
from lifecycle_fixture import REALM, call
from maintenance_human_fixture import HumanMaintenanceFixture
from test_protected_invitations import ProtectedInvitations
from profile_transition_operations import committed_kind, human_target


def install(helper, config):
    # install_self_source already installs the reviewed platform combined profile.
    config['bindings'][0]['accountOperations'].append({'authority':'PLATFORM','selfOnly':False,
        'targetProfiles':sorted(['platform-v1', next(p['id'] for p in config['profiles']
            if p['kind']=='TENANT_ADMIN' and 'consultant' not in p['realmRoles'])]),
        'operations':['account.delete']})
    return config


def protected_created(test,helper,platform):
    previous=helper.scope
    if platform:helper.scope=lambda:ProtectedInvitations.scope(helper)
    try:approval,attempt,scope,approved,create=helper.approved_creation()
    finally:helper.scope=previous
    status,opened=helper.protected_machine_request('create',approval,create,actor='ACCOUNT_CREATE',attempt=attempt)
    test.assertEqual(201,status)
    commit={key:create[key] for key in ('approvalReceipt','scopeDigest','authorizationRevision','creationFingerprint','execution')}
    commit.update(accountId=opened['accountId'],creationProof=opened['creationProof'],localCommit={'journalVersion':1,'outboxId':str(uuid.uuid4()),'effectsDigest':'a'*64})
    status,terminal=helper.protected_machine_request('commit',approval,commit,actor='ACCOUNT_CREATE',attempt=attempt)
    test.assertEqual(200,status);test.assertEqual('COMMITTED',terminal['state'])
    return opened['accountId'],create


def exercise(test,helper,primary,observed):
    records=observed['administratorIdentityRemoval']={}
    old=(helper.account_id,helper.creation_input)
    try:
        for family in ('ORDINARY','TENANT_ADMIN','PLATFORM_ADMIN'):
            if family=='ORDINARY':account,creation=committed_kind(test,helper,'CONSULTANT_AGENCY_ADMIN','consultant-agency-admin')
            else:account,creation=protected_created(test,helper,family=='PLATFORM_ADMIN')
            helper.account_id=account;helper.creation_input=creation
            native=helper.admin('GET','/users/'+account);target=human_target(helper,account,native)
            def read():
                status,current=HumanMaintenanceFixture.invoke(helper,'read',{'target':target},primary,200)
                test.assertEqual(200,status);return current
            current=read()
            if family!='ORDINARY':
                addition={'target':target,'operationId':str(uuid.uuid4()),'expectedState':current['state'],
                    'change':{'transition':'ADD_CONSULTANT_IDENTITY','profileId':'platform-consultant-v2' if family=='PLATFORM_ADMIN' else 'tenant-consultant-v2','profileVersion':2}}
                status,result=HumanMaintenanceFixture.invoke(helper,'profile-transition',addition,primary,200)
                test.assertEqual(200,status);test.assertEqual('UPDATED',result['result']);current=read()
            before=helper.admin('GET','/users/'+account);credentials=helper.admin('GET','/users/'+account+'/credentials')
            body={'target':target,'operationId':str(uuid.uuid4()),'expectedState':current['state'],
                'change':{'transition':'REMOVE_ADMINISTRATOR_IDENTITY','group':'/human-roles/consultant'}}
            status,result=HumanMaintenanceFixture.invoke(helper,'profile-transition',body,primary,200)
            test.assertEqual(200,status);test.assertEqual('UPDATED',result['result'])
            test.assertEqual((status,result),HumanMaintenanceFixture.invoke(helper,'profile-transition',body,primary,200))
            after=helper.admin('GET','/users/'+account);test.assertEqual(before,after)
            test.assertEqual(credentials,helper.admin('GET','/users/'+account+'/credentials'))
            test.assertEqual([helper.group_id('/human-roles/consultant')],[g['id'] for g in helper.admin('GET','/users/'+account+'/groups')])
            current=read();test.assertEqual({'consultant','group-chat-consultant'},set(current['effectiveRoles']))
            test.assertEqual(target['tenantId'],current['tenantId'])
            login_status,login=call(helper.base,'POST','/realms/'+REALM+'/protocol/openid-connect/token',
                {'grant_type':'password','client_id':'protected-human-web','username':before['username'],'password':creation['account']['password'],'scope':'openid'},form=True)
            test.assertEqual(200,login_status)
            own=copy.deepcopy(target);own['origin'].update(kind='SELF',humanSubject=account,humanAuthority=None)
            own_status,own_state=HumanMaintenanceFixture.invoke(helper,'read',{'target':own},login['access_token'],200)
            test.assertEqual(200,own_status);test.assertEqual(account,own_state['id']);test.assertEqual(target['tenantId'],own_state['tenantId'])
            changed=copy.deepcopy(body);changed['operationId']=str(uuid.uuid4());changed['expectedState']=current['state']
            test.assertEqual(403,HumanMaintenanceFixture.invoke(helper,'profile-transition',changed,primary,403)[0])
            records[family]={'nativeGrantAndRemoval':True,'sameUuidTenantProfileCredentialsAndEnabled':True,
                'exactRetry':True,'ordinarySelfAfterOriginalLineage':True,'repeatRemovalRefused':True}
    finally:helper.account_id,helper.creation_input=old


def pure_deletion(test,helper,primary,observed):
    records=observed['pureAdministratorDeletion']={};old=(helper.account_id,helper.creation_input)
    try:
        for family in ('ORDINARY','TENANT_ADMIN','PLATFORM_ADMIN'):
            if family=='ORDINARY':account,creation=committed_kind(test,helper,'AGENCY_ADMIN','agency-admin')
            else:account,creation=protected_created(test,helper,family=='PLATFORM_ADMIN')
            helper.account_id=account;helper.creation_input=creation
            native=helper.admin('GET','/users/'+account);groups=helper.admin('GET','/users/'+account+'/groups')
            target=human_target(helper,account,native)
            status,current=HumanMaintenanceFixture.invoke(helper,'read',{'target':target},primary,200);test.assertEqual(200,status)
            body={'target':target,'operationId':str(uuid.uuid4()),'expectedState':current['state'],'change':{}}
            status,result=HumanMaintenanceFixture.invoke(helper,'delete',body,primary,200)
            test.assertEqual(200,status);test.assertEqual('DELETED',result['result'])
            test.assertEqual(404,call(helper.base,'GET','/admin/realms/'+REALM+'/users/'+account,token=helper.installer)[0])
            test.assertEqual((status,result),HumanMaintenanceFixture.invoke(helper,'delete',body,primary,200))
            replacement={key:copy.deepcopy(native[key]) for key in ('id','username','enabled','email','firstName','lastName','attributes') if key in native}
            replacement['createdTimestamp']=native['createdTimestamp']+1000
            helper.admin('POST','/partialImport',{'ifResourceExists':'FAIL','users':[replacement]})
            defaults=helper.admin('GET','/users/'+account+'/role-mappings/realm')
            if defaults:helper.admin('DELETE','/users/'+account+'/role-mappings/realm',defaults)
            for group in groups:helper.admin('PUT','/users/'+account+'/groups/'+group['id'])
            test.assertEqual(403,HumanMaintenanceFixture.invoke(helper,'delete',body,primary,403)[0])
            test.assertEqual(account,helper.admin('GET','/users/'+account)['id'])
            records[family]={'nativeDelete':True,'exactRetryAfterAccountGone':True,'sameUuidReplacementRetryDenied':True}
        account,creation=committed_kind(test,helper,'CONSULTANT_AGENCY_ADMIN','consultant-agency-admin')
        helper.account_id=account;helper.creation_input=creation
        before=helper.admin('GET','/users/'+account);target=human_target(helper,account,before)
        status,current=HumanMaintenanceFixture.invoke(helper,'read',{'target':target},primary,200);test.assertEqual(200,status)
        body={'target':target,'operationId':str(uuid.uuid4()),'expectedState':current['state'],'change':{}}
        test.assertEqual(403,HumanMaintenanceFixture.invoke(helper,'delete',body,primary,403)[0])
        test.assertEqual(before,helper.admin('GET','/users/'+account));records['combinedRefused']=True
    finally:helper.account_id,helper.creation_input=old


def consultant_removal(test, helper, primary, observed):
    """Exact inverse transition preserves Administrator; ordinary replay grants no general read."""
    from ordinary_consultant_operations import login, target as ordinary_target
    from ordinary_operator_operations import replace_native
    records = observed['consultantIdentityRemoval'] = {}
    old = helper.account_id, helper.creation_input
    try:
        for family in ('ORDINARY', 'TENANT_ADMIN', 'PLATFORM_ADMIN', 'ADOPTED_ORDINARY'):
            if family == 'ORDINARY':
                account, creation = committed_kind(test, helper, 'CONSULTANT_AGENCY_ADMIN', 'consultant-agency-admin')
            elif family == 'ADOPTED_ORDINARY':
                account = type(helper).adopted_admin_cases['consultant-agency-admin'][0]
                creation = {'account': {'username': helper.admin('GET', '/users/' + account)['username']}}
            else:
                account, creation = protected_created(test, helper, family == 'PLATFORM_ADMIN')
            helper.account_id, helper.creation_input = account, creation
            native = helper.admin('GET', '/users/' + account)
            selected = human_target(helper, account, native)
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': selected}, primary, 200)
            test.assertEqual(200, status)
            if family in ('TENANT_ADMIN', 'PLATFORM_ADMIN'):
                group = helper.admin('GET', '/users/' + account + '/groups')[0]['id']
                pure = next(p for p in type(helper).installed_configuration['profiles'] if p['groupId'] == group)
                addition = {'target': selected, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                            'change': {'transition': 'ADD_CONSULTANT_IDENTITY',
                                       'profileId': 'platform-consultant-v2' if family == 'PLATFORM_ADMIN' else 'tenant-consultant-v2',
                                       'profileVersion': 2}}
                test.assertEqual(200, HumanMaintenanceFixture.invoke(helper, 'profile-transition', addition, primary, 200)[0])
                status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': selected}, primary, 200)
                test.assertEqual(200, status)
                change = {'transition': 'REMOVE_CONSULTANT_IDENTITY', 'profileId': pure['id'], 'profileVersion': pure['version']}
                expected_roles = set(pure['realmRoles'])
            else:
                change = {'transition': 'REMOVE_CONSULTANT_IDENTITY', 'group': '/human-roles/agency-admin'}
                expected_roles = {'restricted-agency-admin', 'user-admin'}
            before = helper.admin('GET', '/users/' + account)
            credentials = helper.admin('GET', '/users/' + account + '/credentials')
            body = {'target': selected, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': change}
            status, result = HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, primary, 200)
            test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
            test.assertEqual((status, result), HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, primary, 200))
            test.assertEqual(before, helper.admin('GET', '/users/' + account))
            test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
            status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': selected}, primary, 200)
            test.assertEqual(200, status); test.assertEqual(expected_roles, set(current['effectiveRoles']))
            test.assertEqual(selected['tenantId'], current['tenantId'])
            changed = copy.deepcopy(body); changed['operationId'] = str(uuid.uuid4()); changed['expectedState'] = current['state']
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'profile-transition', changed, primary, 403)[0])
            add_change = {'transition': 'ADD_CONSULTANT_IDENTITY'}
            if family in ('TENANT_ADMIN', 'PLATFORM_ADMIN'):
                add_change.update(profileId='platform-consultant-v2' if family == 'PLATFORM_ADMIN' else 'tenant-consultant-v2', profileVersion=2)
            else:
                add_change['group'] = '/human-roles/consultant-agency-admin'
            readded = {'target': selected, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': add_change}
            test.assertEqual(200, HumanMaintenanceFixture.invoke(helper, 'profile-transition', readded, primary, 200)[0])
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, primary, 403)[0])
            records[family] = {'sameUuidTenantBirthProfileCredentialsAndEnabled': True,
                               'exactAdministratorRoleSubset': True, 'originalReceiptReplay': True,
                               'repeatRemovalDenied': True, 'readdedConsultantCannotBorrowOldRemoval': True}
        source, source_creation = committed_kind(test, helper, 'AGENCY_ADMIN', 'agency-admin')
        source_token = login(test, helper, source, source_creation)
        account, creation = committed_kind(test, helper, 'CONSULTANT_AGENCY_ADMIN', 'consultant-agency-admin')
        helper.account_id, helper.creation_input = account, creation
        selected = ordinary_target(helper, account, source)
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': selected}, source_token, 200)
        test.assertEqual(200, status)
        before = helper.admin('GET', '/users/' + account); credentials = helper.admin('GET', '/users/' + account + '/credentials')
        body = {'target': selected, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                'change': {'transition': 'REMOVE_CONSULTANT_IDENTITY', 'group': '/human-roles/agency-admin'}}
        status, result = HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, source_token, 200)
        test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
        test.assertEqual((status, result), HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, source_token, 200))
        test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'read', {'target': selected}, source_token, 403)[0])
        for command, change in [('deactivate', {}), ('delete', {}), ('profile', {'firstName': 'No', 'lastName': 'Access', 'email': 'no@fixture.invalid'})]:
            denied = {'target': selected, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'], 'change': change}
            test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, command, denied, source_token, 403)[0])
        test.assertEqual(before, helper.admin('GET', '/users/' + account))
        test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
        changed = copy.deepcopy(body); changed['change']['group'] = '/human-roles/consultant'
        test.assertEqual(409, HumanMaintenanceFixture.invoke(helper, 'profile-transition', changed, source_token, 409)[0])
        replace_native(test, helper, account)
        test.assertEqual(403, HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, source_token, 403)[0])
        records['restrictedPeer'] = {'originalReplayWithoutPureAdminRead': True, 'generalCrudStillDenied': True,
                                     'changedBytesDenied': True, 'recreatedTargetDenied': True}
        account, creation = committed_kind(test, helper, 'CONSULTANT_AGENCY_ADMIN', 'consultant-agency-admin')
        helper.account_id, helper.creation_input = account, creation
        own = login(test, helper, account, creation); selected = ordinary_target(helper, account, account)
        status, current = HumanMaintenanceFixture.invoke(helper, 'read', {'target': selected}, own, 200)
        test.assertEqual(200, status)
        before = helper.admin('GET', '/users/' + account); credentials = helper.admin('GET', '/users/' + account + '/credentials')
        body = {'target': selected, 'operationId': str(uuid.uuid4()), 'expectedState': current['state'],
                'change': {'transition': 'REMOVE_CONSULTANT_IDENTITY', 'group': '/human-roles/agency-admin'}}
        status, result = HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, own, 200)
        test.assertEqual(200, status); test.assertEqual('UPDATED', result['result'])
        stale_status, stale = HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, own, 403)
        test.assertEqual(403, stale_status); test.assertNotIn('receipt', stale)
        fresh = login(test, helper, account, creation)
        test.assertEqual((status, result), HumanMaintenanceFixture.invoke(helper, 'profile-transition', body, fresh, 200))
        test.assertEqual(before, helper.admin('GET', '/users/' + account))
        test.assertEqual(credentials, helper.admin('GET', '/users/' + account + '/credentials'))
        records['ordinaryOwn'] = {'freshSameHumanJwtRequired': True, 'explicitCurrentAndDesiredSources': True,
                                  'originalReceiptReplay': True, 'nativeAdministratorPreserved': True}
    finally:
        helper.account_id, helper.creation_input = old
