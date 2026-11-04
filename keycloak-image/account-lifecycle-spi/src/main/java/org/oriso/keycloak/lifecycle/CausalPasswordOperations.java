package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Response;
import java.util.*;
import java.util.function.Supplier;
import org.keycloak.models.*;

/** Only the two fixed, checked ADMIN causal routes call this closed native journal. */
final class CausalPasswordOperations {
  static Response read(KeycloakSession session, LifecycleAuthorization crypto, Map<String,Set<String>> mappings,
      Supplier<GeneralPolicy> policies, GeneralPolicy configured, LifecycleAuthorization.CheckedMachine machine, CausalPasswordRequest causal) {
    lockRealm(session);
    var claim = find(session, crypto, machine, causal);
    if (claim != null) return saved(session, crypto, machine, causal, claim, null);
    return Response.ok(current(session, crypto, mappings, policies, configured, causal)).header("Cache-Control","no-store").build();
  }

  static Response mutate(KeycloakSession session, LifecycleAuthorization crypto, Map<String,Set<String>> mappings,
      Supplier<GeneralPolicy> policies, GeneralPolicy configured, LifecycleAuthorization.CheckedMachine machine, CausalPasswordRequest causal, JsonNode body, Runnable freshCommand) {
    lockRealm(session); var request=causal.command();
    var claim=find(session,crypto,machine,causal);
    if (claim!=null) return saved(session,crypto,machine,causal,claim,body);
    var em=CurrentNativeHumanIdentity.entityManager(session);
    if (em.find(AccountMaintenanceOperation.class,session.getContext().getRealm().getId()+":"+request.operationId(),LockModeType.PESSIMISTIC_WRITE)!=null) conflict();
    // Actual locked committed/adopted profile, tenant, exact recipient and current setup action.
    var current=current(session,crypto,mappings,policies,configured,causal);
    causal.requireLive();
    if (machine.nativeAuth().getToken().getExp()==null || machine.nativeAuth().getToken().getExp()<=java.time.Instant.now().getEpochSecond()) deny();
    if (!LifecycleAuthorization.equal(request.expectedState(),current.path("state").asText())) {
      reserve(session,crypto,machine,causal,body);
      return MaintenanceResults.noEffect(session,crypto,machine,request,body,409);
    }
    var realm=session.getContext().getRealm(); var user=session.users().getUserById(realm,request.accountId());
    var cache=session.getProvider(org.keycloak.models.cache.UserCache.class);
    if(cache!=null && user!=null){cache.evict(realm,user);user=session.users().getUserById(realm,request.accountId());}
    if(user==null) conflict();
    var policy=session.getProvider(org.keycloak.policy.PasswordPolicyManagerProvider.class)
        .validate(realm,user,request.change().path("password").textValue());
    reserve(session,crypto,machine,causal,body);
    if(policy!=null) return MaintenanceResults.noEffect(session,crypto,machine,request,body,400);
    causal.requireLive(); freshCommand.run();
    // No definite refusal can be signed beyond this first native effect.
    if(!user.credentialManager().updateCredential(UserCredentialModel.password(request.change().path("password").textValue())))
      throw new IllegalStateException("Password effect did not complete");
    user.removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
    session.users().setNotBeforeForUser(realm,user,org.keycloak.common.util.Time.currentTime());
    for(var nativeSession:session.sessions().getUserSessionsStream(realm,user).toList())
      org.keycloak.services.managers.AuthenticationManager.backchannelLogout(session,realm,nativeSession,
          session.getContext().getUri(),session.getContext().getConnection(),session.getContext().getRequestHeaders(),true);
    if(session.sessions().getUserSessionsStream(realm,user).findAny().isPresent()) throw new IllegalStateException("Session revocation did not complete");
    em.flush();
    var fresh=AccountLifecycleResource.lockedSnapshot(em,request.accountId());
    for(var action:fresh.path("requiredActions")) if("UPDATE_PASSWORD".equals(action.asText())) throw new IllegalStateException("Required action effect did not complete");
    return MaintenanceResults.updated(session,crypto,machine,request,body);
  }

  private static JsonNode current(KeycloakSession session,LifecycleAuthorization crypto,Map<String,Set<String>> mappings,
      Supplier<GeneralPolicy> policies,GeneralPolicy configured,CausalPasswordRequest causal){
    causal.requireLive();
    return !OrdinaryAccountOperations.adoptedTarget(session,configured,causal.target()) && ProtectedAccountOperations.protectedTarget(session,causal.target())
        ? ProtectedAccountOperations.readCausal(session,crypto,causal)
        : OrdinaryAccountOperations.readCausal(session,crypto,mappings,policies.get(),causal);
  }
  private static void lockRealm(KeycloakSession session){
    var em=CurrentNativeHumanIdentity.entityManager(session);
    var realm=em.find(org.keycloak.models.jpa.entities.RealmEntity.class,session.getContext().getRealm().getId(),LockModeType.PESSIMISTIC_WRITE);
    if(realm==null)deny();em.refresh(realm);
  }
  private static String id(KeycloakSession session,LifecycleAuthorization crypto,CausalPasswordRequest causal){
    var key=JSON.createObjectNode();key.put("realmId",session.getContext().getRealm().getId());
    key.put("kind",causal.workflow().path("kind").asText());key.put("claimId",causal.workflow().path("claimId").asText());
    key.set("claimVersion",causal.workflow().path("claimVersion"));return crypto.mac("maintenance-password-claim-id/v1",key);
  }
  private static CausalPasswordClaim find(KeycloakSession session,LifecycleAuthorization crypto,
      LifecycleAuthorization.CheckedMachine machine,CausalPasswordRequest causal){
    var em=CurrentNativeHumanIdentity.entityManager(session);var row=em.find(CausalPasswordClaim.class,id(session,crypto,causal),LockModeType.PESSIMISTIC_WRITE);
    if(row==null)return null;em.refresh(row);
    if(!LifecycleAuthorization.equal(crypto.mac("maintenance-password-claim/v1",binding(row)),row.bindingMac))deny();
    if(!session.getContext().getRealm().getId().equals(row.realmId)||!causal.target().accountId().equals(row.accountId)
        ||!machine.clientId().equals(row.ownerClient)||!machine.subject().equals(row.ownerSubject)
        ||!causal.workflow().path("kind").asText().equals(row.kind)||!causal.workflow().path("claimId").asText().equals(row.claimId)
        ||causal.workflow().path("claimVersion").longValue()!=row.claimVersion
        ||!LifecycleAuthorization.equal(crypto.mac("maintenance-password-target/v1",causal.target().target()),row.targetDigest)
        ||!LifecycleAuthorization.equal(crypto.mac("maintenance-password-workflow/v1",causal.workflow()),row.workflowDigest))conflict();
    return row;
  }
  private static Response saved(KeycloakSession session,LifecycleAuthorization crypto,LifecycleAuthorization.CheckedMachine machine,
      CausalPasswordRequest causal,CausalPasswordClaim claim,JsonNode body){
    var em=CurrentNativeHumanIdentity.entityManager(session);var prior=em.find(AccountMaintenanceOperation.class,claim.realmId+":"+claim.operationId,LockModeType.PESSIMISTIC_WRITE);
    if(prior==null)deny();em.refresh(prior);
    if(!claim.realmId.equals(prior.realmId)||!claim.accountId.equals(prior.accountId)||!claim.operationId.equals(prior.operationId)
        ||!"password-reset".equals(prior.command)||!machine.clientId().equals(prior.ownerClient)||!machine.subject().equals(prior.ownerSubject)
        ||!LifecycleAuthorization.equal(claim.intentDigest,prior.intentDigest)||!LifecycleAuthorization.equal(claim.expectedState,prior.expectedState))deny();
    if(body!=null && (!claim.operationId.equals(causal.command().operationId())
        ||!LifecycleAuthorization.equal(crypto.mac("maintenance-intent",body),claim.intentDigest)))conflict();
    var request=new MaintenanceRequest("password-reset",claim.accountId,causal.target().target(),claim.operationId,claim.expectedState,null,null,null,null);
    return MaintenanceResults.saved(prior,crypto,request);
  }
  private static void reserve(KeycloakSession session,LifecycleAuthorization crypto,LifecycleAuthorization.CheckedMachine machine,
      CausalPasswordRequest causal,JsonNode body){
    var row=new CausalPasswordClaim();row.id=id(session,crypto,causal);row.realmId=session.getContext().getRealm().getId();row.accountId=causal.target().accountId();
    row.kind=causal.workflow().path("kind").asText();row.claimId=causal.workflow().path("claimId").asText();row.claimVersion=causal.workflow().path("claimVersion").longValue();
    row.ownerClient=machine.clientId();row.ownerSubject=machine.subject();row.targetDigest=crypto.mac("maintenance-password-target/v1",causal.target().target());
    row.workflowDigest=crypto.mac("maintenance-password-workflow/v1",causal.workflow());row.operationId=causal.command().operationId();
    row.intentDigest=crypto.mac("maintenance-intent",body);row.expectedState=causal.command().expectedState();row.bindingMac=crypto.mac("maintenance-password-claim/v1",binding(row));
    CurrentNativeHumanIdentity.entityManager(session).persist(row);
  }
  private static JsonNode binding(CausalPasswordClaim row){
    var value=JSON.createObjectNode();value.put("v",1);value.put("realmId",row.realmId);value.put("accountId",row.accountId);
    value.put("kind",row.kind);value.put("claimId",row.claimId);value.put("claimVersion",row.claimVersion);value.put("ownerClient",row.ownerClient);value.put("ownerSubject",row.ownerSubject);
    value.put("targetDigest",row.targetDigest);value.put("workflowDigest",row.workflowDigest);value.put("operationId",row.operationId);value.put("intentDigest",row.intentDigest);value.put("expectedState",row.expectedState);return value;
  }
  private static void conflict(){throw new ClientErrorException("Causal password claim conflicts",409);}
  private CausalPasswordOperations(){}
}
