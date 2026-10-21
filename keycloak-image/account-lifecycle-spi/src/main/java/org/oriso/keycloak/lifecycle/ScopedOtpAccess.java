package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resource.RealmResourceProvider;

/** One provided boundary for the original OTP route. Assertions never construct a grant. */
public final class ScopedOtpAccess {
  private ScopedOtpAccess() {}

  public static Response requireSelfRead(KeycloakSession session, String exactPathUsername,
      String accountTargetHeader, String taskContextHeader, String fullImmediateHumanHeader,
      Function<VerifiedOtpTarget, Response> read) {
    return guarded(session, () -> configuration(session).readOtpSelf(session, exactPathUsername,
        accountTargetHeader, taskContextHeader, fullImmediateHumanHeader, read));
  }

  public static Response requireSelfAppSetup(KeycloakSession session, String exactPathUsername,
      byte[] raw, String taskContextHeader, String fullImmediateHumanHeader,
      Function<VerifiedOtpTarget, Response> setup) {
    return guarded(session, () -> configuration(session).appSetupOtpSelf(session, exactPathUsername,
        raw, taskContextHeader, fullImmediateHumanHeader, setup));
  }

  private static AccountLifecycleFactory configuration(KeycloakSession session) {
    var factory = session.getKeycloakSessionFactory().getProviderFactory(
        RealmResourceProvider.class, "oriso-account-lifecycle");
    if (!(factory instanceof AccountLifecycleFactory)) deny();
    return (AccountLifecycleFactory) factory;
  }

  private static Response guarded(KeycloakSession session, Supplier<Response> checked) {
    try {
      return checked.get();
    } catch (WebApplicationException rejected) {
      if (session.getTransactionManager().isActive()) session.getTransactionManager().setRollbackOnly();
      throw new WebApplicationException(Response.status(rejected.getResponse().getStatus())
          .type(MediaType.APPLICATION_JSON).entity(Map.of("error", "OTP request rejected"))
          .header("Cache-Control", "no-store").build());
    } catch (RuntimeException unavailable) {
      if (session.getTransactionManager().isActive()) session.getTransactionManager().setRollbackOnly();
      // Native exceptions can contain credentials or token data. Do not propagate their text/cause.
      throw new WebApplicationException(Response.status(503).type(MediaType.APPLICATION_JSON)
          .entity(Map.of("error", "OTP request could not complete"))
          .header("Cache-Control", "no-store").build());
    }
  }

  static Response checkedSelfRead(KeycloakSession session, LifecycleAuthorization authorization,
      Map<String, Set<String>> mappings, GeneralPolicy policy, String username,
      String targetHeader, String proofHeader, String humanHeader,
      Function<VerifiedOtpTarget, Response> read) {
    // Cache the canonical machine before native human authentication changes ambient context.
    var machine = authorization.requireMachine(session, "ACCOUNT_ADMIN");
    if (targetHeader == null || targetHeader.length() > 8192 || username == null
        || username.isBlank() || username.length() > 255
        || username.chars().anyMatch(c -> c < 32 || c == 127)) bad();
    var target = parse(targetHeader);
    String account = uuid(text(target, "accountId", 36, false));
    var materialized = JSON.createObjectNode();
    materialized.set("target", target);
    materialized.put("username", username);
    materialized.putNull("otp");
    var realm = session.getContext().getRealm();
    authorization.verifyCommand(proofHeader, machine, "oriso-otp", "OTP", "otp.read", "GET",
        "realm/" + realm.getId() + "/account/" + account, materialized);
    var body = JSON.createObjectNode();
    body.set("target", target);
    var request = MaintenanceRequest.parse("read", account, body);
    // Realm -> committed provenance -> current human -> native user/credential locks.
    var current = new MaintenanceTarget(session, authorization, mappings)
        .readOtpSelf(request, policy, humanHeader);
    return invoke(session, username, account, current, null, read);
  }

  static Response checkedSelfAppSetup(KeycloakSession session, LifecycleAuthorization authorization,
      Map<String, Set<String>> mappings, GeneralPolicy policy, String username,
      byte[] raw, String proofHeader, String humanHeader,
      Function<VerifiedOtpTarget, Response> setup) {
    var machine = authorization.requireMachine(session, "ACCOUNT_ADMIN");
    if (username == null || username.isBlank() || username.length() > 255
        || username.chars().anyMatch(c -> c < 32 || c == 127)) bad();
    var body = parse(raw);
    String account = uuid(text(body.path("target"), "accountId", 36, false));
    var request = ScopedOtpRequest.parse("otp.app-setup", account, body);
    var materialized = body.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode) materialized).put("username", username);
    var realm = session.getContext().getRealm();
    authorization.verifyCommand(proofHeader, machine, "oriso-otp", "OTP", "otp.app-setup", "PUT",
        "realm/" + realm.getId() + "/account/" + account, materialized);
    var read = JSON.createObjectNode();
    read.set("target", request.target());
    var target = MaintenanceRequest.parse("read", account, read);
    if (policy == null) deny();
    var em = session.getProvider(org.keycloak.connections.jpa.JpaConnectionProvider.class).getEntityManager();
    var lockedRealm = em.find(org.keycloak.models.jpa.entities.RealmEntity.class,
        realm.getId(), jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
    if (lockedRealm == null) deny();
    em.refresh(lockedRealm);
    String id = realm.getId() + ":" + request.operationId();
    var prior = em.find(AccountMaintenanceOperation.class, id, jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
    String digest = authorization.mac("otp-intent", materialized);
    if (prior != null) {
      em.refresh(prior);
      if (!realm.getId().equals(prior.realmId) || !account.equals(prior.accountId)
          || !request.operation().equals(prior.command) || !machine.clientId().equals(prior.ownerClient)
          || !machine.subject().equals(prior.ownerSubject)
          || !LifecycleAuthorization.equal(digest, prior.intentDigest)
          || !LifecycleAuthorization.equal(request.expectedState(), prior.expectedState))
        throw new jakarta.ws.rs.ClientErrorException("OTP operation conflicts", 409);
      // The immutable operation is retry provenance. Reauthorize the actual current human,
      // then return before mutable credential/CAS lookup or a second enrollment effect.
      policy.requireSelfOtpAppSetup(session, target, humanHeader);
      var saved = parse(prior.resultJson);
      int status = saved.path("status").asInt();
      if (!Set.of(200, 201, 401).contains(status)) deny();
      return Response.status(status).entity(saved).header("Cache-Control", "no-store").build();
    }
    var current = new MaintenanceTarget(session, authorization, mappings)
        .readOtpSelfAppSetup(target, policy, humanHeader);
    if (!LifecycleAuthorization.equal(request.expectedState(), current.path("state").asText()))
      throw new jakarta.ws.rs.ClientErrorException("Current OTP target state conflicts", 409);
    var nativeResponse = invoke(session, username, account, current, request, setup);
    int status = nativeResponse.getStatus();
    var nativeResult = JSON.valueToTree(nativeResponse.getEntity());
    if (status == 200 || status == 201) {
      fields(nativeResult, "info");
      text(nativeResult, "info", 512, false);
    } else if (status == 401) {
      fields(nativeResult, "error", "error_description");
      text(nativeResult, "error", 100, false);
      text(nativeResult, "error_description", 512, false);
    } else throw new IllegalStateException("Unsupported app OTP outcome");
    var outcome = JSON.createObjectNode();
    outcome.put("realmId", realm.getId());
    outcome.put("accountId", account);
    outcome.put("operationId", request.operationId());
    outcome.put("operation", request.operation());
    outcome.put("ownerClient", machine.clientId());
    outcome.put("ownerSubject", machine.subject());
    outcome.put("intentDigest", digest);
    outcome.put("previousState", request.expectedState());
    outcome.set("tenantId", request.target().path("tenantId"));
    outcome.put("originDigest", authorization.mac("otp-origin", request.target().path("origin")));
    outcome.put("status", status);
    outcome.put("resultDigest", authorization.mac("otp-result", nativeResult));
    var result = JSON.createObjectNode();
    result.put("operationId", request.operationId());
    result.put("accountId", account);
    result.put("status", status);
    result.set("result", nativeResult);
    result.put("receipt", authorization.receipt("otp-operation-receipt", outcome));
    var saved = new AccountMaintenanceOperation();
    saved.id = id;
    saved.realmId = realm.getId();
    saved.operationId = request.operationId();
    saved.accountId = account;
    saved.command = request.operation();
    saved.ownerClient = machine.clientId();
    saved.ownerSubject = machine.subject();
    saved.intentDigest = digest;
    saved.expectedState = request.expectedState();
    saved.resultJson = canonical(result);
    em.persist(saved);
    if (status == 201 && realm.isAdminEventsEnabled()) {
      var event = new org.keycloak.events.admin.AdminEvent();
      event.setTime(System.currentTimeMillis());
      event.setRealmId(realm.getId());
      event.setOperationType(org.keycloak.events.admin.OperationType.CREATE);
      event.setResourceType(org.keycloak.events.admin.ResourceType.USER);
      event.setResourcePath("accounts/" + account + "/otp");
      var details = new org.keycloak.events.admin.AuthDetails();
      details.setRealmId(realm.getId());
      details.setClientId(machine.clientId());
      details.setUserId(machine.subject());
      event.setAuthDetails(details);
      session.getProvider(org.keycloak.events.EventStoreProvider.class).onEvent(event, false);
    }
    // Credential effect, terminal invalid-code outcome and immutable receipt commit together.
    em.flush();
    return Response.status(status).entity(result).header("Cache-Control", "no-store").build();
  }

  private static Response invoke(KeycloakSession session, String username, String account,
      com.fasterxml.jackson.databind.JsonNode current, ScopedOtpRequest request,
      Function<VerifiedOtpTarget, Response> action) {
    var realm = session.getContext().getRealm();
    if (!username.equals(current.path("username").textValue())) deny();
    var user = session.users().getUserById(realm, account);
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) {
      cache.evict(realm, user);
      user = session.users().getUserById(realm, account);
    }
    if (user == null || !username.equals(user.getUsername())) deny();
    var lifetime = new Lifetime(session);
    try {
      var checked = new VerifiedOtpTarget(lifetime, realm, user, request);
      var response = action.apply(checked);
      lifetime.check();
      if (response == null) throw new IllegalStateException("OTP callback did not return a response");
      return Response.fromResponse(response).header("Cache-Control", "no-store").build();
    } finally {
      lifetime.open = false;
    }
  }

  /** Same live request and transaction only. It contains no human bearer or transferable authority. */
  public static final class VerifiedOtpTarget {
    private final Lifetime lifetime;
    private final RealmModel realm;
    private final UserModel user;
    private final ScopedOtpRequest request;
    private VerifiedOtpTarget(Lifetime lifetime, RealmModel realm, UserModel user, ScopedOtpRequest request) {
      this.lifetime = lifetime;
      this.realm = realm;
      this.user = user;
      this.request = request;
    }
    public KeycloakSession session() { lifetime.check(); return lifetime.session; }
    public RealmModel realm() { lifetime.check(); return realm; }
    public UserModel user() { lifetime.check(); return user; }
    public String initialCode() { lifetime.check(); if (request == null) deny(); return request.otp().path("initialCode").textValue(); }
    public String secret() { lifetime.check(); if (request == null) deny(); return request.otp().path("secret").textValue(); }
    @Override public String toString() { return "VerifiedOtpTarget[redacted]"; }
  }

  private static final class Lifetime {
    private final KeycloakSession session;
    private final KeycloakTransactionManager transaction;
    private final Thread owner = Thread.currentThread();
    private volatile boolean open = true;
    private Lifetime(KeycloakSession session) {
      this.session = session;
      transaction = session.getTransactionManager();
      check();
      transaction.enlistAfterCompletion(new AbstractKeycloakTransaction() {
        protected void commitImpl() { open = false; }
        protected void rollbackImpl() { open = false; }
      });
    }
    private void check() {
      if (!open || Thread.currentThread() != owner || session.getTransactionManager() != transaction
          || !transaction.isActive() || transaction.getRollbackOnly()) deny();
    }
  }
}
