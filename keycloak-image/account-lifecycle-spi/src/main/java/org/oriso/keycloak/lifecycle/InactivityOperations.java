package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import java.util.*;
import java.util.function.Supplier;
import org.keycloak.models.KeycloakSession;

/** Explicit scheduled grant or actual manual PLATFORM source; no synthesized human or password. */
final class InactivityOperations {
  static JsonNode read(KeycloakSession session,LifecycleAuthorization crypto,Map<String,Set<String>> mappings,
      Supplier<GeneralPolicy> policies,GeneralPolicy configured,MaintenanceRequest request,String human){
    if(request.workflow()==null)deny();
    if("INACTIVITY".equals(request.target().path("origin").path("kind").asText())&&human!=null)deny();
    if(adoptedOrdinaryTarget(session,configured,request))
      return OrdinaryAccountOperations.read(session,crypto,mappings,human==null?configured:policies.get(),request,human);
    return ProtectedAccountOperations.protectedTarget(session,request)
        ? ProtectedAccountOperations.readCurrentOperation(session,crypto,request,human)
        : OrdinaryAccountOperations.read(session,crypto,mappings,policies.get(),request,human);
  }
  static void mutate(KeycloakSession session,LifecycleAuthorization crypto,Map<String,Set<String>> mappings,
      Supplier<GeneralPolicy> policies,GeneralPolicy configured,LifecycleAuthorization.CheckedMachine machine,MaintenanceRequest request,JsonNode body,String human){
    var current=read(session,crypto,mappings,policies,configured,request,human);
    if(!LifecycleAuthorization.equal(request.expectedState(),current.path("state").asText()))throw MaintenancePreflightRefusal.current(409);
    boolean suspend="deactivate".equals(request.command());
    if(suspend && "INACTIVITY".equals(request.target().path("origin").path("kind").asText())
        &&request.workflow().path("dueAt").longValue()>java.time.Instant.now().getEpochSecond())throw MaintenancePreflightRefusal.current(403);
    boolean enabled=suspend?false:restoreEnabled(session,crypto,machine,request);
    var realm=session.getContext().getRealm();var user=session.users().getUserById(realm,request.accountId());
    var cache=session.getProvider(org.keycloak.models.cache.UserCache.class);
    if(cache!=null&&user!=null){cache.evict(realm,user);user=session.users().getUserById(realm,request.accountId());}
    if(user==null)throw MaintenancePreflightRefusal.current(409);
    if(suspend)record(session,crypto,machine,request,body,current.path("enabled").booleanValue());
    // All authenticated definite refusal checks precede this first provider write.
    user.setEnabled(enabled);
    if(suspend){
      session.users().setNotBeforeForUser(realm,user,org.keycloak.common.util.Time.currentTime());
      for(var nativeSession:session.sessions().getUserSessionsStream(realm,user).toList())
        org.keycloak.services.managers.AuthenticationManager.backchannelLogout(session,realm,nativeSession,
            session.getContext().getUri(),session.getContext().getConnection(),session.getContext().getRequestHeaders(),true);
      if(session.sessions().getUserSessionsStream(realm,user).findAny().isPresent())throw new IllegalStateException("Native session revocation incomplete");
    }
    var em=CurrentNativeHumanIdentity.entityManager(session);em.flush();
    var fresh=AccountLifecycleResource.lockedSnapshot(em,request.accountId());
    if(!fresh.path("enabled").isBoolean()||fresh.path("enabled").booleanValue()!=enabled)throw new IllegalStateException("Native status effect incomplete");
  }
  private static boolean adoptedOrdinaryTarget(KeycloakSession session,GeneralPolicy configured,MaintenanceRequest request){
    if(configured==null||!configured.adoptedAccounts.containsKey(request.accountId()))return false;
    var em=CurrentNativeHumanIdentity.entityManager(session);var realm=session.getContext().getRealm();
    var locked=em.find(org.keycloak.models.jpa.entities.RealmEntity.class,realm.getId(),LockModeType.PESSIMISTIC_WRITE);
    if(locked==null)deny();em.refresh(locked);
    var attempts=em.createQuery("select a.id from AccountLifecycleAttempt a where a.realmId=:realm and a.accountId=:account",String.class)
        .setParameter("realm",realm.getId()).setParameter("account",request.accountId()).setMaxResults(2).getResultList();
    if(!attempts.isEmpty())return false;
    if(ProtectedInvitationFactory.configuredAdoptedTarget(session,request.accountId()))deny();
    // This is a locator only. The selected receiver must check its grant, baseline and full native profile.
    return true;
  }
  private static void record(KeycloakSession session,LifecycleAuthorization crypto,LifecycleAuthorization.CheckedMachine machine,
      MaintenanceRequest request,JsonNode body,boolean enabled){
    var value=JSON.createObjectNode();value.put("v",1);value.put("realmId",session.getContext().getRealm().getId());
    value.put("accountId",request.accountId());value.put("operationId",request.operationId());value.put("ownerClient",machine.clientId());
    value.put("ownerSubject",machine.subject());value.put("intentDigest",crypto.mac("maintenance-intent",body));value.put("previousState",request.expectedState());
    value.set("target",request.target());value.set("workflow",request.workflow());value.put("originalEnabled",enabled);
    var row=new InactivitySuspension();row.realmId=session.getContext().getRealm().getId();row.accountId=request.accountId();row.operationId=request.operationId();
    row.id=row.realmId+":"+row.operationId;row.bindingJson=canonical(value);row.bindingMac=crypto.mac("maintenance-inactivity-suspension/v1",value);
    CurrentNativeHumanIdentity.entityManager(session).persist(row);
  }
  private static boolean restoreEnabled(KeycloakSession session,LifecycleAuthorization crypto,LifecycleAuthorization.CheckedMachine machine,
      MaintenanceRequest request){
    var em=CurrentNativeHumanIdentity.entityManager(session);String realm=session.getContext().getRealm().getId();
    String original=request.workflow().path("suspensionOperationId").asText();
    var row=em.find(InactivitySuspension.class,realm+":"+original,LockModeType.PESSIMISTIC_WRITE);
    if(row==null)throw MaintenancePreflightRefusal.current(409);em.refresh(row);var value=parse(row.bindingJson);
    fields(value,"v","realmId","accountId","operationId","ownerClient","ownerSubject","intentDigest","previousState","target","workflow","originalEnabled");
    if(!realm.equals(row.realmId)||!request.accountId().equals(row.accountId)||!original.equals(row.operationId)
        ||!LifecycleAuthorization.equal(crypto.mac("maintenance-inactivity-suspension/v1",value),row.bindingMac)
        ||number(value,"v",true)!=1||!realm.equals(value.path("realmId").asText())||!request.accountId().equals(value.path("accountId").asText())
        ||!original.equals(value.path("operationId").asText())||!machine.clientId().equals(value.path("ownerClient").asText())
        ||!machine.subject().equals(value.path("ownerSubject").asText())||!value.path("originalEnabled").isBoolean()
        ||!request.target().path("accountId").equals(value.path("target").path("accountId"))
        ||!request.target().path("tenantId").equals(value.path("target").path("tenantId")))throw MaintenancePreflightRefusal.current(409);
    for(String field:List.of("kind","revision","assignedMonths","lastActivity","dueAt"))
      if(!request.workflow().path(field).equals(value.path("workflow").path(field)))throw MaintenancePreflightRefusal.current(409);
    if(!"SUSPEND".equals(value.path("workflow").path("action").asText()))throw MaintenancePreflightRefusal.current(409);
    var prior=em.find(AccountMaintenanceOperation.class,row.id,LockModeType.PESSIMISTIC_WRITE);if(prior==null)throw MaintenancePreflightRefusal.current(409);em.refresh(prior);
    if(!realm.equals(prior.realmId)||!request.accountId().equals(prior.accountId)||!original.equals(prior.operationId)||!"deactivate".equals(prior.command)
        ||!machine.clientId().equals(prior.ownerClient)||!machine.subject().equals(prior.ownerSubject)
        ||!prior.intentDigest.equals(value.path("intentDigest").asText())||!prior.expectedState.equals(value.path("previousState").asText())
        ||!"UPDATED".equals(parse(prior.resultJson).path("result").asText()))throw MaintenancePreflightRefusal.current(409);
    var originalBody=JSON.createObjectNode();originalBody.set("target",value.path("target"));originalBody.set("workflow",value.path("workflow"));
    originalBody.put("operationId",original);originalBody.put("expectedState",prior.expectedState);originalBody.putObject("change");
    if(!LifecycleAuthorization.equal(crypto.mac("maintenance-intent",originalBody),prior.intentDigest))deny();
    var parsed=MaintenanceRequest.parse("deactivate",request.accountId(),originalBody);
    if(MaintenanceResults.saved(prior,crypto,parsed).getStatus()!=200)deny();
    boolean enabled=value.path("originalEnabled").booleanValue();
    if(request.change().path("restoreEnabled").booleanValue()!=enabled)throw MaintenancePreflightRefusal.current(409);
    return enabled;
  }
  private InactivityOperations(){}
}
