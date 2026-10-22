package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import java.util.Map;
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

  AccountMaintenanceResource(KeycloakSession session, LifecycleAuthorization auth,
      Map<String, Set<String>> mappings, Supplier<GeneralPolicy> humanPolicies) {
    this.session = session;
    this.auth = auth;
    this.humanPolicies = humanPolicies;
    this.targets = new MaintenanceTarget(session, auth, mappings);
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
      if (ProtectedAccountOperations.selected(request.target())) {
        var current = ProtectedAccountOperations.protectedTarget(session, request)
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
      var current = ProtectedAccountOperations.protectedTarget(session, causal.target())
          ? ProtectedAccountOperations.readCausal(session, auth, causal)
          : OrdinaryAccountOperations.readCausal(session, auth, mappings, humanPolicies.get(), causal);
      return Response.ok(current).header("Cache-Control", "no-store").build();
    });
  }

  @POST
  @Path("v1/accounts/{account}/delete")
  public Response delete(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof) {
    return guarded(() -> {
      var machine = auth.requireMachine(session, "ACCOUNT_ADMIN");
      var body = parse(raw);
      var realm = session.getContext().getRealm();
      auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_MAINTENANCE",
          "account.delete", "POST", "realm/" + realm.getId() + "/account/" + account, body);
      var request = MaintenanceRequest.parse("delete", account, body);
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
  @Path("v1/accounts/{account}/deactivate")
  public Response deactivate(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof,
      @HeaderParam("X-ORISO-Human-Authorization") String human) {
    return selfMutation("deactivate", account, raw, proof, human);
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
    if (!Set.of("locale", "profile", "email", "ordinary-profile", "deactivate", "reactivate", "password", "self-password").contains(command)) deny();
    return guarded(() -> {
      var machine = auth.requireMachine(session, "ACCOUNT_ADMIN");
      var body = parse(raw);
      var realm = session.getContext().getRealm();
      auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_MAINTENANCE",
          "account." + command, "POST", "realm/" + realm.getId() + "/account/" + account, body);
      var request = MaintenanceRequest.parse(command, account, body);
      boolean humanAdmin = ProtectedAccountOperations.selected(request.target())
          && "HUMAN_ADMIN".equals(request.target().path("origin").path("kind").asText())
          && Set.of("profile", "email", "ordinary-profile", "deactivate", "reactivate").contains(command);
      if (!("SELF".equals(request.target().path("origin").path("kind").asText()) || humanAdmin)) deny();
      var humanPolicy = humanAdmin ? null : humanPolicies.get();
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
        // The immutable operation is the retry provenance; verify the current actual human,
        // then return before mutable target/CAS resolution or any second native effect.
        if (humanAdmin) HumanAdminSource.require(session, auth, request, rawHumanBearer);
        else humanPolicy.requireSelf(session, request, rawHumanBearer);
        return MaintenanceResults.saved(prior, auth, request);
      }
      request.requireEffectDeadline();
      if (machine.nativeAuth().getToken().getExp() == null
          || machine.nativeAuth().getToken().getExp() <= java.time.Instant.now().getEpochSecond()) deny();
      auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_MAINTENANCE",
          "account." + command, "POST", "realm/" + realm.getId() + "/account/" + account, body);
      try {
        if (humanAdmin) {
          if (ProtectedAccountOperations.protectedTarget(session, request))
            ProtectedAccountOperations.mutate(session, auth, request, rawHumanBearer);
          else OrdinaryAccountOperations.mutate(session, auth, mappings, humanPolicies.get(), request, body, rawHumanBearer);
        } else if ("locale".equals(command)) targets.locale(request, humanPolicy, rawHumanBearer);
        else if ("profile".equals(command)) targets.profile(request, humanPolicy, rawHumanBearer);
        else if (Set.of("password", "self-password").contains(command)) targets.password(request, humanPolicy, rawHumanBearer);
        else deny();
      } catch (MaintenancePreflightRefusal refused) {
        if (!humanAdmin) throw refused;
        return MaintenanceResults.noEffect(session, auth, machine, request, body, refused.getResponse().getStatus());
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
