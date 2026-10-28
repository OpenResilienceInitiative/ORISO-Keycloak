package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import java.util.Map;
import java.util.List;
import java.util.function.Supplier;
import jakarta.persistence.LockModeType;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.jpa.entities.RealmEntity;
import java.util.Set;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/** Finite reads, current-human self locale and receipt-backed deletion. */
@jakarta.ws.rs.ext.Provider
@jakarta.enterprise.inject.Vetoed
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public final class AccountMaintenanceResource implements RealmResourceProvider {
  private final KeycloakSession session;
  private final LifecycleAuthorization auth;
  private final MaintenanceTarget targets;
  private final Map<String, Set<String>> mappings;
  private final Supplier<GeneralPolicy> humanPolicies;
  private final GeneralPolicy configuredPolicy;

  AccountMaintenanceResource(KeycloakSession session, LifecycleAuthorization auth,
      Map<String, Set<String>> mappings, Supplier<GeneralPolicy> humanPolicies) {
    this(session,auth,mappings,humanPolicies,null);
  }
  AccountMaintenanceResource(KeycloakSession session,LifecycleAuthorization auth,Map<String,Set<String>> mappings,
      Supplier<GeneralPolicy> humanPolicies,GeneralPolicy configuredPolicy) {
    this.session = session;
    this.auth = auth;
    this.humanPolicies = humanPolicies;
    this.configuredPolicy = configuredPolicy;
    this.targets = new MaintenanceTarget(session, auth, mappings, configuredPolicy);
    this.mappings = mappings;
  }

  @POST
  @Path("v1/availability")
  public Response usernameAvailability(byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof) {
    return guarded(() -> {
      var machine = auth.requireMachine(session, "ACCOUNT_CREATE");
      var body = parse(raw);
      var realm = session.getContext().getRealm();
      auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_AVAILABILITY",
          "account.username-availability", "POST",
          "realm/" + realm.getId() + "/availability/username", body);
      var selector = MaintenanceRequest.availability(body);
      if (!"username".equals(selector.path("selector").textValue())) deny();
      String username = text(selector, "value", 255, false);
      return Response.ok(Map.of("available", session.users().getUserByUsername(realm, username) == null))
          .header("Cache-Control", "no-store").build();
    });
  }

  @POST
  @Path("v1/availability/invitation-email")
  public Response invitationEmailAvailability(byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String rawHumanBearer) {
    return guarded(() -> {
      var machine=auth.requireMachine(session,"ACCOUNT_ADMIN");
      var body=parse(raw);
      var realm=session.getContext().getRealm();
      auth.verifyCommand(proof,machine,"oriso-account-maintenance","ACCOUNT_MAINTENANCE",
          "account.invitation-email-availability","POST","realm/"+realm.getId()+"/availability/invitation-email",body);
      var request=InvitationEmailAvailability.parse(body);
      var tenant=request.tenantId()==null?JSON.getNodeFactory().nullNode():JSON.valueToTree(request.tenantId());
      var source=HumanAdminSource.require(session,auth,request.origin(),tenant,rawHumanBearer);
      request.requireTenant(source);
      if("PROTECTED".equals(request.family()))source.requireProtectedInvitationProfile(session,request);
      else {
        var policy=humanPolicies.get();
        var profile=policy.profile(request.profileId(),request.profileVersion());
        if(!request.kind().equals(LifecycleGroups.allowedKind(profile.realmRoles)))deny();
        policy.requireInvitationRead(source,profile);
        policy.validateProfile(session,profile);
      }
      return Response.ok(Map.of("available",session.users().getUserByEmail(realm,request.email())==null))
          .header("Cache-Control","no-store").build();
    });
  }

  @POST
  @Path("v1/accounts/{account}/read")
  public Response read(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String rawHumanBearer) {
    return guarded(() -> {
      var machine = auth.requireMachine(session, "ACCOUNT_ADMIN");
      var body = parse(raw);
      auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_MAINTENANCE",
          "account.read", "POST",
          "realm/" + session.getContext().getRealm().getId() + "/account/" + account, body);
      var request = MaintenanceRequest.parse("read", account, body);
      if(request.workflow()!=null&&"IMPORT".equals(request.workflow().path("kind").asText()))
        return Response.ok(ImportOperations.read(session,auth,mappings,humanPolicies,configuredPolicy,request,rawHumanBearer)).header("Cache-Control","no-store").build();
      if(request.workflow()!=null)
        return Response.ok(InactivityOperations.read(session,auth,mappings,humanPolicies,configuredPolicy,request,rawHumanBearer)).header("Cache-Control","no-store").build();
      if(OrdinaryAdminSource.selected(request.target()))
        return Response.ok(OrdinaryAccountOperations.read(session,auth,mappings,humanPolicies.get(),request,rawHumanBearer)).header("Cache-Control","no-store").build();
      if (ProtectedAccountOperations.selected(request.target())) {
        var current = !OrdinaryAccountOperations.adoptedTarget(session,configuredPolicy,request) && ProtectedAccountOperations.protectedTarget(session, request)
            ? ProtectedAccountOperations.readAccount(session, auth, request, rawHumanBearer)
            : OrdinaryAccountOperations.read(session, auth, mappings, humanPolicies.get(), request, rawHumanBearer);
        return Response.ok(current).header("Cache-Control", "no-store").build();
      }
      var humanPolicy = "SELF".equals(request.target().path("origin").path("kind").asText())
          ? humanPolicies.get() : null;
      return Response.ok(targets.read(request, humanPolicy, rawHumanBearer)).header("Cache-Control", "no-store").build();
    });
  }

  @POST
  @Path("v1/accounts/{account}/password-reset/read")
  public Response causalPasswordRead(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String human) {
    return guarded(() -> {
      var machine = auth.requireMachine(session, "ACCOUNT_ADMIN"); var body = parse(raw);
      auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_MAINTENANCE",
          "account.password-reset.read", "POST", "realm/" + session.getContext().getRealm().getId() + "/account/" + account, body);
      if (human != null) deny();
      var causal = CausalPasswordRequest.read(account, body);
      return CausalPasswordOperations.read(session, auth, mappings, humanPolicies, configuredPolicy, machine, causal);
    });
  }

  @POST
  @Path("v1/accounts/{account}/password-reset")
  public Response causalPassword(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String human) {
    return guarded(() -> {
      var machine = auth.requireMachine(session, "ACCOUNT_ADMIN"); var body = parse(raw);
      auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_MAINTENANCE",
          "account.password-reset", "POST", "realm/" + session.getContext().getRealm().getId() + "/account/" + account, body);
      if (human != null) deny();
      return CausalPasswordOperations.mutate(session, auth, mappings, humanPolicies, configuredPolicy, machine,
          CausalPasswordRequest.mutation(account, body), body, () -> {
            auth.requireMachine(session, "ACCOUNT_ADMIN");
            auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_MAINTENANCE",
                "account.password-reset", "POST", "realm/" + session.getContext().getRealm().getId() + "/account/" + account, body);
          });
    });
  }

  @POST
  @Path("v1/accounts/{account}/delete")
  public Response delete(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String human) {
    return guarded(() -> {
      var machine = auth.requireMachine(session, "ACCOUNT_ADMIN");
      var body = parse(raw);
      var realm = session.getContext().getRealm();
      auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_MAINTENANCE",
          "account.delete", "POST", "realm/" + realm.getId() + "/account/" + account, body);
      var request = MaintenanceRequest.parse("delete", account, body);
      if("HUMAN_ADMIN".equals(request.target().path("origin").path("kind").asText()))
        return AdminAccountDeletion.execute(session,auth,mappings,humanPolicies,configuredPolicy,machine,request,body,human);
      var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
      var lockedRealm = em.find(RealmEntity.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
      if (lockedRealm == null) deny();
      em.refresh(lockedRealm);
      String id = realm.getId() + ":" + request.operationId();
      var prior = em.find(AccountMaintenanceOperation.class, id, LockModeType.PESSIMISTIC_WRITE);
      String digest = auth.mac("maintenance-intent", body);
      if (prior != null) {
        em.refresh(prior);
        if (!realm.getId().equals(prior.realmId) || !account.equals(prior.accountId)
            || !"delete".equals(prior.command) || !machine.clientId().equals(prior.ownerClient)
            || !machine.subject().equals(prior.ownerSubject)
            || !LifecycleAuthorization.equal(digest, prior.intentDigest)
            || !LifecycleAuthorization.equal(request.expectedState(), prior.expectedState))
          throw new ClientErrorException("Maintenance operation conflicts", 409);
        // Exact retry resolves before current target/provenance lookup, including reused native UUIDs.
        return Response.ok(parse(prior.resultJson)).header("Cache-Control", "no-store").build();
      }
      targets.delete(request);
      var outcome = JSON.createObjectNode();
      outcome.put("realmId", realm.getId());
      outcome.put("accountId", account);
      outcome.put("operationId", request.operationId());
      outcome.put("command", "delete");
      outcome.put("ownerClient", machine.clientId());
      outcome.put("ownerSubject", machine.subject());
      outcome.put("intentDigest", digest);
      outcome.put("previousState", request.expectedState());
      outcome.set("tenantId", request.target().path("tenantId"));
      outcome.put("originDigest", auth.mac("maintenance-origin", request.target().path("origin")));
      outcome.put("result", "DELETED");
      var result = JSON.createObjectNode();
      result.put("operationId", request.operationId());
      result.put("accountId", account);
      result.put("result", "DELETED");
      result.put("receipt", auth.receipt("maintenance-operation-receipt", outcome));
      var saved = new AccountMaintenanceOperation();
      saved.id = id;
      saved.realmId = realm.getId();
      saved.operationId = request.operationId();
      saved.accountId = account;
      saved.command = "delete";
      saved.ownerClient = machine.clientId();
      saved.ownerSubject = machine.subject();
      saved.intentDigest = digest;
      saved.expectedState = request.expectedState();
      saved.resultJson = canonical(result);
      em.persist(saved);
      if (realm.isAdminEventsEnabled()) {
        var event = new org.keycloak.events.admin.AdminEvent();
        event.setTime(System.currentTimeMillis());
        event.setRealmId(realm.getId());
        event.setOperationType(org.keycloak.events.admin.OperationType.DELETE);
        event.setResourceType(org.keycloak.events.admin.ResourceType.USER);
        event.setResourcePath("accounts/" + account);
        var details = new org.keycloak.events.admin.AuthDetails();
        details.setRealmId(realm.getId());
        details.setClientId(machine.clientId());
        details.setUserId(machine.subject());
        event.setAuthDetails(details);
        session.getProvider(org.keycloak.events.EventStoreProvider.class).onEvent(event, false);
      }
      em.flush();
      return Response.ok(result).header("Cache-Control", "no-store").build();
    });
  }

  @POST
  @Path("v1/accounts/{account}/locale")
  public Response locale(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String rawHumanBearer) {
    return selfMutation("locale", account, raw, proof, rawHumanBearer);
  }

  @POST
  @Path("v1/accounts/{account}/profile")
  public Response profile(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String rawHumanBearer) {
    return selfMutation("profile", account, raw, proof, rawHumanBearer);
  }

  @POST
  @Path("v1/accounts/{account}/email")
  public Response email(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String human) {
    return selfMutation("email", account, raw, proof, human);
  }

  @POST
  @Path("v1/accounts/{account}/ordinary-profile")
  public Response ordinaryProfile(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String human) {
    return selfMutation("ordinary-profile", account, raw, proof, human);
  }

  @POST
  @Path("v1/accounts/{account}/profile-transition")
  public Response profileTransition(@PathParam("account") String account,byte[] raw,
      @HeaderParam("X-ORISO-Task-Context")String proof,@HeaderParam("X-ORISO-Human-Authorization")String human){
    return selfMutation("profile-transition",account,raw,proof,human);
  }

  @POST
  @Path("v1/accounts/{account}/reassign-tenant")
  public Response reassignTenant(@PathParam("account") String account,byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,@HeaderParam("X-ORISO-Human-Authorization") String human) {
    return selfMutation("reassign-tenant",account,raw,proof,human);
  }

  @POST
  @Path("v1/accounts/{account}/deactivate")
  public Response deactivate(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String human) {
    return selfMutation("deactivate", account, raw, proof, human);
  }

  @POST
  @Path("v1/accounts/{account}/deactivate/outcome")
  public Response selfDeactivationOutcome(@PathParam("account") String account,byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String human) {
    return guarded(() -> {
      var machine=auth.requireMachine(session,"ACCOUNT_ADMIN");
      if(human!=null)deny();
      var body=parse(raw);var realm=session.getContext().getRealm();
      auth.verifyCommand(proof,machine,"oriso-account-maintenance","ACCOUNT_MAINTENANCE",
          "account.deactivate.outcome","POST","realm/"+realm.getId()+"/account/"+account,body);
      var request=MaintenanceRequest.parse("deactivate",account,body);
      if(!"SELF".equals(request.target().path("origin").path("kind").asText())
          ||!account.equals(request.target().path("origin").path("humanSubject").asText())
          ||!request.target().path("origin").path("humanAuthority").isNull()||request.workflow()!=null)deny();
      var em=session.getProvider(JpaConnectionProvider.class).getEntityManager();
      var locked=em.find(RealmEntity.class,realm.getId(),LockModeType.PESSIMISTIC_WRITE);
      if(locked==null)deny();em.refresh(locked);
      var prior=em.find(AccountMaintenanceOperation.class,realm.getId()+":"+request.operationId(),LockModeType.PESSIMISTIC_WRITE);
      if(prior==null)throw new ClientErrorException("Original outcome remains unknown",409);
      em.refresh(prior);
      if(!realm.getId().equals(prior.realmId)||!account.equals(prior.accountId)||!"deactivate".equals(prior.command)
          ||!machine.clientId().equals(prior.ownerClient)||!machine.subject().equals(prior.ownerSubject)
          ||!LifecycleAuthorization.equal(auth.mac("maintenance-intent",body),prior.intentDigest)
          ||!LifecycleAuthorization.equal(request.expectedState(),prior.expectedState))
        throw new ClientErrorException("Original outcome conflicts",409);
      var saved=MaintenanceResults.saved(prior,auth,request);
      if(!"UPDATED".equals(parse(prior.resultJson).path("result").asText()))deny();
      SelfDeactivationOutcome.requireSaved(session,auth,mappings,humanPolicies.get(),request,prior);
      return saved;
    });
  }

  @POST
  @Path("v1/accounts/{account}/reactivate")
  public Response reactivate(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String human) {
    return selfMutation("reactivate", account, raw, proof, human);
  }

  @POST
  @Path("v1/accounts/{account}/password")
  public Response password(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String rawHumanBearer) {
    return selfMutation("password", account, raw, proof, rawHumanBearer);
  }

  @POST
  @Path("v1/accounts/{account}/self-password")
  public Response selfPassword(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String rawHumanBearer) {
    return selfMutation("self-password", account, raw, proof, rawHumanBearer);
  }

  private Response selfMutation(String command, String account, byte[] raw, String proof,
      String rawHumanBearer) {
    if (!Set.of("locale", "profile", "email", "ordinary-profile", "deactivate", "reactivate", "reassign-tenant", "profile-transition", "password", "self-password").contains(command)) deny();
    return guarded(() -> {
      var machine = auth.requireMachine(session, "ACCOUNT_ADMIN");
      var body = parse(raw);
      var realm = session.getContext().getRealm();
      auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_MAINTENANCE",
          "account." + command, "POST", "realm/" + realm.getId() + "/account/" + account, body);
      var request = MaintenanceRequest.parse(command, account, body);
      boolean inactivity=request.workflow()!=null&&"INACTIVITY".equals(request.workflow().path("kind").asText());
      boolean importing=request.workflow()!=null&&"IMPORT".equals(request.workflow().path("kind").asText());
      boolean humanAdmin = (ProtectedAccountOperations.selected(request.target())
          ||OrdinaryAdminSource.selected(request.target())&&Set.of("deactivate","profile","ordinary-profile","profile-transition").contains(command))
          && "HUMAN_ADMIN".equals(request.target().path("origin").path("kind").asText())
          && Set.of("profile", "email", "ordinary-profile", "deactivate", "reactivate", "reassign-tenant", "profile-transition").contains(command);
      if (!("SELF".equals(request.target().path("origin").path("kind").asText()) || humanAdmin || inactivity || importing)) deny();
      if(inactivity&&"INACTIVITY".equals(request.target().path("origin").path("kind").asText())&&rawHumanBearer!=null)deny();
      boolean protectedSelf = "SELF".equals(request.target().path("origin").path("kind").asText())
          && ProtectedAccountOperations.selected(request.target());
      var humanPolicy = humanAdmin || inactivity || importing || protectedSelf ? null : humanPolicies.get();
      var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
      var lockedRealm = em.find(RealmEntity.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
      if (lockedRealm == null) deny();
      em.refresh(lockedRealm);
      String id = realm.getId() + ":" + request.operationId();
      var prior = em.find(AccountMaintenanceOperation.class, id, LockModeType.PESSIMISTIC_WRITE);
      String digest = auth.mac("maintenance-intent", body);
      if (prior != null) {
        em.refresh(prior);
        if (!realm.getId().equals(prior.realmId) || !account.equals(prior.accountId)
            || !command.equals(prior.command) || !machine.clientId().equals(prior.ownerClient)
            || !machine.subject().equals(prior.ownerSubject)
            || !LifecycleAuthorization.equal(digest, prior.intentDigest)
            || !LifecycleAuthorization.equal(request.expectedState(), prior.expectedState))
          throw new ClientErrorException("Maintenance operation conflicts", 409);
        // Verify historical checked reach and independently current source/target authority.
        // The saved result never repeats CAS or native effects.
        var saved = MaintenanceResults.saved(prior, auth, request);
        if (humanAdmin) MaintenanceReplayReach.require(session,auth,mappings,humanPolicies,configuredPolicy,request,prior,rawHumanBearer);
        else if(inactivity||importing) {
          if(rawHumanBearer!=null)deny();
          var read = new MaintenanceRequest("read", account, request.target(), null, null, null, null, null, request.workflow());
          boolean refused = "NO_EFFECT".equals(parse(prior.resultJson).path("result").asText());
          // A refusal requires current read reach; a saved effect also needs its logical grant.
          for(var current : refused ? List.of(read) : List.of(read, request)) {
            if(inactivity) InactivityOperations.read(session,auth,mappings,humanPolicies,configuredPolicy,current,null);
            else ImportOperations.read(session,auth,mappings,humanPolicies,configuredPolicy,current,null);
          }
        }
        else SelfAccountOperations.current(session, auth, targets, humanPolicy, request, rawHumanBearer);
        return saved;
      }
      request.requireEffectDeadline();
      if (machine.nativeAuth().getToken().getExp() == null
          || machine.nativeAuth().getToken().getExp() <= java.time.Instant.now().getEpochSecond()) deny();
      auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_MAINTENANCE",
          "account." + command, "POST", "realm/" + realm.getId() + "/account/" + account, body);
      MaintenanceReplayReach.Checked reach=null;
      SelfDeactivationOutcome.Prepared selfDeactivation=null;
      try {
        if(inactivity) reach=InactivityOperations.mutate(session,auth,mappings,humanPolicies,configuredPolicy,machine,request,body,rawHumanBearer);
        else if(importing) reach=ImportOperations.mutate(session,auth,mappings,humanPolicies,configuredPolicy,request,body,rawHumanBearer);
        else if (humanAdmin) {
          if (!OrdinaryAccountOperations.adoptedTarget(session,configuredPolicy,request) && ProtectedAccountOperations.protectedTarget(session, request))
            reach=ProtectedAccountOperations.mutate(session, auth, request, body, rawHumanBearer);
          else reach=OrdinaryAccountOperations.mutate(session, auth, mappings, humanPolicies.get(), request, body, rawHumanBearer);
        } else if("deactivate".equals(command)&&"SELF".equals(request.target().path("origin").path("kind").asText()))
          selfDeactivation=SelfDeactivationOutcome.deactivate(session,auth,mappings,humanPolicy,request,rawHumanBearer);
        else SelfAccountOperations.mutate(session, auth, targets, humanPolicy, request, rawHumanBearer);
      } catch (MaintenancePreflightRefusal refused) {
        return MaintenanceResults.noEffect(session, auth, machine, request, body, refused.getResponse().getStatus(),refused.reach());
      }
      var outcome = JSON.createObjectNode();
      outcome.put("realmId", realm.getId());
      outcome.put("accountId", account);
      outcome.put("operationId", request.operationId());
      outcome.put("command", command);
      outcome.put("ownerClient", machine.clientId());
      outcome.put("ownerSubject", machine.subject());
      outcome.put("intentDigest", digest);
      outcome.put("previousState", request.expectedState());
      outcome.set("tenantId", request.target().path("tenantId"));
      outcome.put("originDigest", auth.mac("maintenance-origin", request.target().path("origin")));
      outcome.put("result", "UPDATED");
      var result = JSON.createObjectNode();
      result.put("operationId", request.operationId());
      result.put("accountId", account);
      result.put("result", "UPDATED");
      result.put("receipt", auth.receipt("maintenance-operation-receipt", outcome));
      var saved = new AccountMaintenanceOperation();
      saved.id = id;
      saved.realmId = realm.getId();
      saved.operationId = request.operationId();
      saved.accountId = account;
      saved.command = command;
      saved.ownerClient = machine.clientId();
      saved.ownerSubject = machine.subject();
      saved.intentDigest = digest;
      saved.expectedState = request.expectedState();
      saved.resultJson = canonical(result);
      if(humanAdmin)saved.replayReachJson=MaintenanceReplayReach.seal(auth,saved,request,reach);
      if(selfDeactivation!=null)saved.replayReachJson=SelfDeactivationOutcome.seal(auth,saved,request,selfDeactivation);
      em.persist(saved);
      if (realm.isAdminEventsEnabled()) {
        var event = new org.keycloak.events.admin.AdminEvent();
        event.setTime(System.currentTimeMillis());
        event.setRealmId(realm.getId());
        event.setOperationType(org.keycloak.events.admin.OperationType.UPDATE);
        event.setResourceType(org.keycloak.events.admin.ResourceType.USER);
        event.setResourcePath("accounts/" + account);
        var details = new org.keycloak.events.admin.AuthDetails();
        details.setRealmId(realm.getId());
        details.setClientId(machine.clientId());
        details.setUserId(machine.subject());
        event.setAuthDetails(details);
        session.getProvider(org.keycloak.events.EventStoreProvider.class).onEvent(event, false);
      }
      em.flush();
      return Response.ok(result).header("Cache-Control", "no-store").build();
    });
  }

  private Response guarded(Supplier<Response> command) {
    try {
      return command.get();
    } catch (WebApplicationException failure) {
      session.getTransactionManager().setRollbackOnly();
      throw new WebApplicationException(Response.status(failure.getResponse().getStatus())
          .type(MediaType.APPLICATION_JSON).entity(Map.of("error", "Maintenance request rejected"))
          .header("Cache-Control", "no-store").build());
    } catch (RuntimeException failure) {
      session.getTransactionManager().setRollbackOnly();
      // No token, account body, credential, native exception message or representation is logged.
      org.jboss.logging.Logger.getLogger(AccountMaintenanceResource.class)
          .errorf("Maintenance transaction rolled back: %s", failure.getClass().getName());
      throw new WebApplicationException(Response.status(503).type(MediaType.APPLICATION_JSON)
          .entity(Map.of("error", "Maintenance request could not complete"))
          .header("Cache-Control", "no-store").build());
    }
  }

  public Object getResource() { return this; }
  public void close() {}
}
