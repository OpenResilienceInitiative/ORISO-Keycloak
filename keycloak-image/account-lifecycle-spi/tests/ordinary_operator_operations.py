"""Restricted ordinary source parity, current grants and original native birth through real HTTP."""
import copy
import uuid
from lifecycle_fixture import REALM,call
from maintenance_human_fixture import HumanMaintenanceFixture
from profile_transition_operations import committed_kind,human_target


def replace_native(test,helper,account):
    native=helper.admin('GET','/users/'+account);groups=helper.admin('GET','/users/'+account+'/groups')
    helper.admin('DELETE','/users/'+account)
    replacement={key:copy.deepcopy(native[key]) for key in ('id','username','enabled','email','firstName','lastName','attributes') if key in native}
    replacement['createdTimestamp']=native['createdTimestamp']+1000
    helper.admin('POST','/partialImport',{'ifResourceExists':'FAIL','users':[replacement]})
    defaults=helper.admin('GET','/users/'+account+'/role-mappings/realm')
    if defaults:helper.admin('DELETE','/users/'+account+'/role-mappings/realm',defaults)
    for group in groups:helper.admin('PUT','/users/'+account+'/groups/'+group['id'])
    test.assertNotEqual(native['createdTimestamp'],helper.admin('GET','/users/'+account)['createdTimestamp'])


def exercise(test,helper,primary,observed):
    records=observed['restrictedOrdinaryOperators']={};old=(helper.account_id,helper.creation_input)
    try:
        source,source_creation=committed_kind(test,helper,'AGENCY_ADMIN','agency-admin')
        source_native=helper.admin('GET','/users/'+source)
        status,login=call(helper.base,'POST','/realms/'+REALM+'/protocol/openid-connect/token',
            {'grant_type':'password','client_id':'protected-human-web','username':source_native['username'],
             'password':source_creation['account']['password'],'scope':'openid'},form=True)
        test.assertEqual(200,status);human=login['access_token']
        target_account,creation=committed_kind(test,helper,'ASKER','user');helper.account_id=target_account;helper.creation_input=creation
        target=human_target(helper,target_account,helper.admin('GET','/users/'+target_account))
        target['origin'].update(humanSubject=source,humanAuthority='ORDINARY_ACCOUNT_OPERATIONS_V1')
        status,current=HumanMaintenanceFixture.invoke(helper,'read',{'target':target},human,200);test.assertEqual(200,status)
        wrong=copy.deepcopy(target);wrong['tenantId']='999'
        test.assertEqual(403,HumanMaintenanceFixture.invoke(helper,'read',{'target':wrong},human,403)[0])
        body={'target':target,'operationId':str(uuid.uuid4()),'expectedState':current['state'],'change':{}}
        test.assertEqual(403,HumanMaintenanceFixture.invoke(helper,'profile',dict(body,change={'firstName':'ungranted','lastName':'name','email':current['email']}),human,403)[0])
        status,result=HumanMaintenanceFixture.invoke(helper,'deactivate',body,human,200);test.assertEqual(200,status)
        test.assertEqual('UPDATED',result['result']);test.assertFalse(helper.admin('GET','/users/'+target_account)['enabled'])
        test.assertEqual((status,result),HumanMaintenanceFixture.invoke(helper,'deactivate',body,human,200))
        source_group=helper.group_id('/human-roles/agency-admin');role=helper.admin('GET','/roles/user-admin')
        helper.admin('DELETE','/groups/'+source_group+'/role-mappings/realm',[role])
        try:test.assertEqual(403,HumanMaintenanceFixture.invoke(helper,'deactivate',body,human,403)[0])
        finally:helper.admin('POST','/groups/'+source_group+'/role-mappings/realm',[role])
        records['currentOrdinarySource']={'readAndDeactivate':True,'crossTenantAndUnreviewedOperationDenied':True,'exactRetry':True,'withdrawnSourceGrantReplayDenied':True}
        for phase in ('before-first-read','between-read-and-effect'):
            account,creation=committed_kind(test,helper,'ASKER','user');helper.account_id=account;helper.creation_input=creation
            target=human_target(helper,account,helper.admin('GET','/users/'+account))
            if phase=='between-read-and-effect':
                status,current=HumanMaintenanceFixture.invoke(helper,'read',{'target':target},primary,200);test.assertEqual(200,status)
            replace_native(test,helper,account)
            if phase=='before-first-read':status,_=HumanMaintenanceFixture.invoke(helper,'read',{'target':target},primary,403)
            else:status,_=HumanMaintenanceFixture.invoke(helper,'deactivate',{'target':target,'operationId':str(uuid.uuid4()),'expectedState':current['state'],'change':{}},primary,403)
            test.assertEqual(403,status);test.assertTrue(helper.admin('GET','/users/'+account)['enabled'])
            records[phase]={'sameUuidNewNativeBirthDenied':True,'replacementEnabledPreserved':True}
    finally:helper.account_id,helper.creation_input=old
