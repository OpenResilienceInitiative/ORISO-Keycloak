package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Response;
import java.util.*;
import java.util.function.Supplier;
import org.keycloak.models.KeycloakSession;

/** Explicit pure-Administrator deletion. Combined identities always use the preserving transition. */
final class AdminAccountDeletion {
  static Response execute(KeycloakSession session,LifecycleAuthorization crypto,Map<String,Set<String>> mappings,
      Supplier<GeneralPolicy> policies,GeneralPolicy configured,LifecycleAuthorization.CheckedMachine machine,
      MaintenanceRequest request,JsonNode body,String human){
    if(!"delete".equals(request.command())||!"HUMAN_ADMIN".equals(request.target().path("origin").path("kind").asText())
        ||!ProtectedAccountOperations.selected(request.target()))deny();
    var realm=session.getContext().getRealm();var em=CurrentNativeHumanIdentity.entityManager(session);
    var lock=em.find(org.keycloak.models.jpa.entities.RealmEntity.class,realm.getId(),LockModeType.PESSIMISTIC_WRITE);
    if(lock==null)deny();em.refresh(lock);
    String id=realm.getId()+":"+request.operationId(),digest=crypto.mac("maintenance-intent",body);
    var prior=em.find(AccountMaintenanceOperation.class,id,LockModeType.PESSIMISTIC_WRITE);
    if(prior!=null){
      em.refresh(prior);
      if(!realm.getId().equals(prior.realmId)||!request.accountId().equals(prior.accountId)||!"delete".equals(prior.command)
          ||!machine.clientId().equals(prior.ownerClient)||!machine.subject().equals(prior.ownerSubject)
          ||!LifecycleAuthorization.equal(digest,prior.intentDigest)||!LifecycleAuthorization.equal(request.expectedState(),prior.expectedState))
        throw new ClientErrorException(409);
      var saved=parse(prior.resultJson);fields(saved,"operationId","accountId","result","receipt");
      if(!request.operationId().equals(saved.path("operationId").asText())||!request.accountId().equals(saved.path("accountId").asText())
          ||!"DELETED".equals(saved.path("result").asText())||!LifecycleAuthorization.equal(saved.path("receipt").asText(),
          crypto.receipt("maintenance-operation-receipt",MaintenanceResults.payload(session,crypto,machine,request,digest,"DELETED"))))deny();
      // Unlike domain tombstone lookup, a human deletion never authorizes a recreated UUID.
      if(!em.createNativeQuery("select ID from USER_ENTITY where ID=:account and REALM_ID=:realm for update")
          .setParameter("account",request.accountId()).setParameter("realm",realm.getId()).getResultList().isEmpty())deny();
      var source=HumanAdminSource.require(session,crypto,request,human);
      var entries=MaintenanceReplayReach.envelope(crypto,prior,request);
      if(entries.size()!=1)deny();
      var entry=entries.path(0);MaintenanceReplayReach.requireOriginal(session,source,policies,request,entry);
      if("PROTECTED".equals(entry.path("family").asText())){
        var historical=ProtectedOrdinaryTransfer.historical(session,crypto,request.accountId()).lineage();
        if(!"PROTECTED".equals(historical.kind())||!entry.path("profileId").asText().equals(historical.profileId())
            ||entry.path("profileVersion").longValue()!=historical.profileVersion()||!entry.path("tenantId").equals(historical.tenant()))deny();
        pure(historical.nativeProfile().path("realmRoles"),true);
      }else{
        var historical=OrdinaryAccountOperations.deletedProfile(session,crypto,mappings,policies.get(),request.accountId());
        if(!historical.profile().id.equals(entry.path("profileId").asText())||historical.profile().version!=entry.path("profileVersion").longValue()
            ||!historical.tenant().equals(entry.path("tenantId")))deny();
        pure(JSON.valueToTree(new TreeSet<>(historical.profile().realmRoles)),false);
        var attempts=em.createQuery("select a from AccountLifecycleAttempt a where a.realmId=:realm and a.accountId=:account",AccountLifecycleAttempt.class)
            .setParameter("realm",realm.getId()).setParameter("account",request.accountId()).setLockMode(LockModeType.PESSIMISTIC_WRITE).setMaxResults(2).getResultList();
        if(attempts.size()>1)deny();if(attempts.size()==1){em.refresh(attempts.get(0));OriginalNativeBirth.authenticated(crypto,attempts.get(0));}
      }
      return Response.ok(saved).header("Cache-Control","no-store").build();
    }
    boolean protectedTarget=!OrdinaryAccountOperations.adoptedTarget(session,configured,request)&&ProtectedAccountOperations.protectedTarget(session,request);
    JsonNode current=protectedTarget?ProtectedAccountOperations.readCurrentOperation(session,crypto,request,human)
        :OrdinaryAccountOperations.read(session,crypto,mappings,policies.get(),request,human);
    pure(current.path("effectiveRoles"),protectedTarget);
    var reach=protectedTarget?ProtectedAccountOperations.checkedReach(session,crypto,request,human)
        :OrdinaryAccountOperations.checkedReach(session,crypto,mappings,policies.get(),request,human);
    if(!LifecycleAuthorization.equal(request.expectedState(),current.path("state").asText()))throw new ClientErrorException(409);
    var user=session.users().getUserById(realm,request.accountId());
    var cache=session.getProvider(org.keycloak.models.cache.UserCache.class);
    if(cache!=null&&user!=null){cache.evict(realm,user);user=session.users().getUserById(realm,request.accountId());}
    if(user==null||!session.users().removeUser(realm,user))throw new IllegalStateException("Pure Administrator removal did not complete");
    var result=JSON.createObjectNode();result.put("operationId",request.operationId());result.put("accountId",request.accountId());result.put("result","DELETED");
    result.put("receipt",crypto.receipt("maintenance-operation-receipt",MaintenanceResults.payload(session,crypto,machine,request,digest,"DELETED")));
    var saved=new AccountMaintenanceOperation();saved.id=id;saved.realmId=realm.getId();saved.operationId=request.operationId();saved.accountId=request.accountId();
    saved.command="delete";saved.ownerClient=machine.clientId();saved.ownerSubject=machine.subject();saved.intentDigest=digest;saved.expectedState=request.expectedState();
    saved.resultJson=canonical(result);saved.replayReachJson=MaintenanceReplayReach.seal(crypto,saved,request,reach);em.persist(saved);em.flush();
    return Response.ok(result).header("Cache-Control","no-store").build();
  }
  static void pure(JsonNode roles,boolean protectedTarget){
    var values=HumanPolicyJson.strings(roles,1,100,255);
    if(values.contains("consultant")||values.contains("group-chat-consultant")
        ||(protectedTarget?!values.contains("tenant-admin")&&!values.contains("single-tenant-admin")
            :!"AGENCY_ADMIN".equals(LifecycleGroups.allowedKind(values))))deny();
  }
  private AdminAccountDeletion(){}
}
