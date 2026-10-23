package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;

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

  public static Response requireSelfAppSetup(KeycloakSession session, String exactPathUsername,
      byte[] raw, String taskContextHeader, String fullImmediateHumanHeader, String bootstrapReceipt,
      Function<VerifiedOtpTarget, Response> setup) {
    if (bootstrapReceipt == null) return requireSelfAppSetup(session, exactPathUsername, raw,
        taskContextHeader, fullImmediateHumanHeader, setup);
    return guarded(session, () -> configuration(session).appSetupOtpProtected(session, exactPathUsername,
        raw, taskContextHeader, fullImmediateHumanHeader, bootstrapReceipt, setup));
  }

  public static Response requireSelfDelete(KeycloakSession session, String exactPathUsername,
      byte[] raw, String taskContextHeader, String fullImmediateHumanHeader,
      Function<VerifiedOtpTarget, Response> delete) {
    return guarded(session, () -> configuration(session).deleteOtpSelf(session, exactPathUsername,
        raw, taskContextHeader, fullImmediateHumanHeader, delete));
  }

  public static Response requireSelfEmailFinish(KeycloakSession session, String exactPathUsername,
      byte[] raw, String taskContextHeader, String fullImmediateHumanHeader,
      Function<VerifiedOtpTarget, Response> finish) {
    return guarded(session, () -> configuration(session).finishEmailOtpSelf(session, exactPathUsername,
        raw, taskContextHeader, fullImmediateHumanHeader, finish));
  }

  public static Response requireSelfEmailFinish(KeycloakSession session, String exactPathUsername,
      byte[] raw, String taskContextHeader, String fullImmediateHumanHeader, String bootstrapReceipt,
      Function<VerifiedOtpTarget, Response> finish) {
    if (bootstrapReceipt == null) return requireSelfEmailFinish(session, exactPathUsername, raw,
        taskContextHeader, fullImmediateHumanHeader, finish);
    return guarded(session, () -> configuration(session).finishEmailOtpProtected(session, exactPathUsername,
        raw, taskContextHeader, fullImmediateHumanHeader, bootstrapReceipt, finish));
  }

  public static Response requireSelfEmailStart(KeycloakSession session, String exactPathUsername,
      byte[] raw, String taskContextHeader, String fullImmediateHumanHeader,
      Function<VerifiedOtpTarget, Response> prepare, Function<VerifiedOtpTarget, Response> send) {
    return guarded(session, () -> configuration(session).startEmailOtpSelf(session, exactPathUsername,
        raw, taskContextHeader, fullImmediateHumanHeader, prepare, send));
  }

  public static Response requireSelfEmailStart(KeycloakSession session, String exactPathUsername,
      byte[] raw, String taskContextHeader, String fullImmediateHumanHeader, String bootstrapReceipt,
      Function<VerifiedOtpTarget, Response> prepare, Function<VerifiedOtpTarget, Response> send) {
    if (bootstrapReceipt == null) return requireSelfEmailStart(session, exactPathUsername, raw,
        taskContextHeader, fullImmediateHumanHeader, prepare, send);
    return guarded(session, () -> configuration(session).startEmailOtpProtected(session, exactPathUsername,
        raw, taskContextHeader, fullImmediateHumanHeader, bootstrapReceipt, prepare, send));
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
      Map<String, Set<String>> mappings, Function<KeycloakSession, GeneralPolicy> policies, String username,
      String targetHeader, String proofHeader, String humanHeader,
      Function<VerifiedOtpTarget, Response> read) {
    // Cache the canonical machine before native human authentication changes ambient context.
    var machine = authorization.requireMachine(session, "ACCOUNT_ADMIN");
    if (targetHeader == null || targetHeader.length() > 24576 || username == null
        || username.isBlank() || username.length() > 255
        || username.chars().anyMatch(c -> c < 32 || c == 127)) bad();
    var target = parse(targetHeader);
    String account = uuid(text(target, "accountId", 36, false));
    var materialized = JSON.createObjectNode();
    materialized.set("target", target);
    materialized.put("username", username);
    materialized.putNull("otp");
    var realm = session.getContext().getRealm();
    if (target.has("bootstrap")) {
      authorization.verifyCommand(proofHeader, machine, "oriso-otp", "OTP", "otp.bootstrap-read", "GET",
          "realm/" + realm.getId() + "/account/" + account, materialized);
      if (humanHeader != null) deny();
      return ProtectedOtpBootstrap.prepare(session, authorization, machine, username, target, user -> {
        var projection = JSON.createObjectNode(); projection.put("username", user.getUsername());
        return invoke(session, authorization, username, account, projection, null, read).response();
      });
    }
    if (targetHeader.length() > 8192) bad();
    authorization.verifyCommand(proofHeader, machine, "oriso-otp", "OTP", "otp.read", "GET",
        "realm/" + realm.getId() + "/account/" + account, materialized);
    var body = JSON.createObjectNode();
    body.set("target", target);
    var request = MaintenanceRequest.parse("read", account, body);
    // Realm -> committed provenance -> current human -> native user/credential locks.
    var current = ProtectedAccountOperations.selected(target)
        ? ProtectedAccountOperations.readSelfOtp(session, authorization, request, humanHeader)
        : new MaintenanceTarget(session, authorization, mappings)
            .readOtpSelf(request, policies.apply(session), humanHeader);
    return invoke(session, authorization, username, account, current, null, read).response();
  }

  static Response checkedProtectedApp(KeycloakSession session, LifecycleAuthorization authorization,
      String username, byte[] raw, String proofHeader, String humanHeader, String bootstrapReceipt,
      Function<VerifiedOtpTarget, Response> setup) {
    var machine = authorization.requireMachine(session, "ACCOUNT_ADMIN");
    if (humanHeader != null || username == null || username.isBlank() || username.length() > 255
        || username.chars().anyMatch(c -> c < 32 || c == 127)) deny();
    var body = parse(raw);
    String account = uuid(text(body.path("target"), "accountId", 36, false));
    var request = ScopedOtpRequest.parse("otp.app-setup", account, body);
    var materialized = body.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode) materialized).put("username", username);
    ((com.fasterxml.jackson.databind.node.ObjectNode) materialized).put("bootstrapReceipt", bootstrapReceipt);
    authorization.verifyCommand(proofHeader, machine, "oriso-otp", "OTP", "otp.bootstrap-app-setup", "PUT",
        "realm/" + session.getContext().getRealm().getId() + "/account/" + account, materialized);
    return ProtectedOtpBootstrap.app(session, authorization, machine, username, request, materialized,
        bootstrapReceipt, user -> {
          var projection = JSON.createObjectNode(); projection.put("username", user.getUsername());
          return invoke(session, authorization, username, account, projection, request, setup).response();
        });
  }

  static Response checkedSelfMutation(KeycloakSession session, LifecycleAuthorization authorization,
      Map<String, Set<String>> mappings, Function<KeycloakSession, GeneralPolicy> policies, String operation, String method, String username,
      byte[] raw, String proofHeader, String humanHeader,
      Function<VerifiedOtpTarget, Response> setup) {
    var machine = authorization.requireMachine(session, "ACCOUNT_ADMIN");
    if (username == null || username.isBlank() || username.length() > 255
        || username.chars().anyMatch(c -> c < 32 || c == 127)) bad();
    var body = parse(raw);
    String account = uuid(text(body.path("target"), "accountId", 36, false));
    var request = ScopedOtpRequest.parse(operation, account, body);
    var materialized = body.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode) materialized).put("username", username);
    var realm = session.getContext().getRealm();
    authorization.verifyCommand(proofHeader, machine, "oriso-otp", "OTP", operation, method,
        "realm/" + realm.getId() + "/account/" + account, materialized);
    var read = JSON.createObjectNode();
    read.set("target", request.target());
    var target = MaintenanceRequest.parse("read", account, read);
    boolean protectedSelf = ProtectedAccountOperations.selected(request.target());
    var policy = protectedSelf ? null : policies.apply(session);
    if (!protectedSelf && policy == null) deny();
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
      // Verify current native provenance and human authority before returning the saved result.
      // Its old CAS is not reapplied and enrollment is never repeated.
      if (protectedSelf) ProtectedAccountOperations.readSelfOperation(session, authorization, target, humanHeader, operation);
      else if ("otp.delete".equals(operation)) new MaintenanceTarget(session, authorization, mappings).readOtpSelfDelete(target, policy, humanHeader);
      else if ("otp.email-finish".equals(operation)) new MaintenanceTarget(session, authorization, mappings).readOtpSelfEmailFinish(target, policy, humanHeader);
      else new MaintenanceTarget(session, authorization, mappings).readOtpSelfAppSetup(target, policy, humanHeader);
      var saved = parse(prior.resultJson);
      int status = saved.path("status").asInt();
      if (!("otp.delete".equals(operation) ? Set.of(200) : Set.of(200, 201, 401)).contains(status)) deny();
      return Response.status(status).entity(saved).header("Cache-Control", "no-store").build();
    }
    var linked = "otp.email-finish".equals(operation) && body.has("emailStartOperationId")
        ? requireLinkedEmailStart(em, realm, authorization, machine, request) : null;
    var targets = new MaintenanceTarget(session, authorization, mappings);
    var current = protectedSelf
        ? ProtectedAccountOperations.readSelfOperation(session, authorization, target, humanHeader, operation)
        : "otp.delete".equals(operation) ? targets.readOtpSelfDelete(target, policy, humanHeader)
        : "otp.email-finish".equals(operation) ? targets.readOtpSelfEmailFinish(target, policy, humanHeader)
        : targets.readOtpSelfAppSetup(target, policy, humanHeader);
    if (!LifecycleAuthorization.equal(request.expectedState(), current.path("state").asText()))
      throw new jakarta.ws.rs.ClientErrorException("Current OTP target state conflicts", 409);
    var invocation = invoke(session, authorization, username, account, current, request, setup, linked);
    var nativeResponse = invocation.response();
    int status = nativeResponse.getStatus();
    var nativeResult = JSON.valueToTree(nativeResponse.getEntity());
    if ("otp.delete".equals(operation) && status != 200)
      throw new IllegalStateException("Unsupported delete OTP outcome");
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
    if ("otp.email-finish".equals(operation)) {
      if (invocation.emailCredential() == null) deny();
      outcome.set("emailCredential", invocation.emailCredential());
      if (linked != null) outcome.put("emailStartOperationId", linked.operationId());
    }
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
    if ((status == 201 || "otp.delete".equals(operation)) && realm.isAdminEventsEnabled()) {
      var event = new org.keycloak.events.admin.AdminEvent();
      event.setTime(System.currentTimeMillis());
      event.setRealmId(realm.getId());
      event.setOperationType("otp.delete".equals(operation)
          ? org.keycloak.events.admin.OperationType.DELETE : org.keycloak.events.admin.OperationType.CREATE);
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

  static Response checkedSelfEmailStart(KeycloakSession session, LifecycleAuthorization authorization,
      Map<String, Set<String>> mappings, Function<KeycloakSession, GeneralPolicy> policies, String username,
      byte[] raw, String proofHeader, String humanHeader,
      Function<VerifiedOtpTarget, Response> prepare, Function<VerifiedOtpTarget, Response> send) {
    return checkedSelfEmailStart(session, authorization, mappings, policies, username, raw,
        proofHeader, humanHeader, prepare, send, EmailPhase.REQUEST);
  }

  private enum EmailPhase { REQUEST, CLAIM, SEND }

  private static Response checkedSelfEmailStart(KeycloakSession session, LifecycleAuthorization authorization,
      Map<String, Set<String>> mappings, Function<KeycloakSession, GeneralPolicy> policies, String username,
      byte[] raw, String proofHeader, String humanHeader,
      Function<VerifiedOtpTarget, Response> prepare, Function<VerifiedOtpTarget, Response> send,
      EmailPhase phase) {
    var machine = authorization.requireMachine(session, "ACCOUNT_ADMIN");
    if (username == null || username.isBlank() || username.length() > 255
        || username.chars().anyMatch(c -> c < 32 || c == 127)) bad();
    var body = parse(raw);
    String account = uuid(text(body.path("target"), "accountId", 36, false));
    var request = ScopedOtpRequest.parse("otp.email-start", account, body);
    var materialized = body.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode) materialized).put("username", username);
    var realm = session.getContext().getRealm();
    authorization.verifyCommand(proofHeader, machine, "oriso-otp", "OTP", "otp.email-start", "PUT",
        "realm/" + realm.getId() + "/account/" + account, materialized);
    var read = JSON.createObjectNode();
    read.set("target", request.target());
    var target = MaintenanceRequest.parse("read", account, read);
    boolean protectedSelf = ProtectedAccountOperations.selected(request.target());
    var policy = protectedSelf ? null : policies.apply(session);
    if (!protectedSelf && policy == null) deny();
    var em = session.getProvider(org.keycloak.connections.jpa.JpaConnectionProvider.class).getEntityManager();
    var lockedRealm = em.find(org.keycloak.models.jpa.entities.RealmEntity.class,
        realm.getId(), jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
    if (lockedRealm == null) deny();
    em.refresh(lockedRealm);
    String id = realm.getId() + ":" + request.operationId();
    String digest = authorization.mac("otp-intent", materialized);
    var prior = em.find(AccountMaintenanceOperation.class, id, jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
    var delivery = em.find(OtpEmailDelivery.class, id, jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
    if (prior != null) {
      em.refresh(prior);
      if (!realm.getId().equals(prior.realmId) || !account.equals(prior.accountId)
          || !"otp.email-start".equals(prior.command) || !machine.clientId().equals(prior.ownerClient)
          || !machine.subject().equals(prior.ownerSubject)
          || !LifecycleAuthorization.equal(digest, prior.intentDigest)
          || !LifecycleAuthorization.equal(request.expectedState(), prior.expectedState))
        throw new jakarta.ws.rs.ClientErrorException("OTP operation conflicts", 409);
      if (delivery == null) deny();
      em.refresh(delivery);
      if (!id.equals(delivery.id) || !realm.getId().equals(delivery.realmId)
          || !account.equals(delivery.accountId) || !LifecycleAuthorization.equal(digest, delivery.intentDigest)) deny();
      if (phase == EmailPhase.REQUEST) {
        if (protectedSelf) ProtectedAccountOperations.emailStart(session, authorization, target, humanHeader);
        else new MaintenanceTarget(session, authorization, mappings).readOtpSelfEmailStart(target, policy, humanHeader);
        if ("SENT".equals(delivery.state) && delivery.finalJson != null)
          return Response.ok(parse(delivery.finalJson)).header("Cache-Control", "no-store").build();
        if (!"READY".equals(delivery.state) || delivery.expiresAt <= java.time.Instant.now().getEpochSecond())
          throw new jakarta.ws.rs.ServiceUnavailableException("OTP delivery outcome is unknown");
        enlistForegroundEmail(session, authorization, mappings, policies, username, raw,
            proofHeader, humanHeader, send);
        return Response.status(202).entity(parse(prior.resultJson)).header("Cache-Control", "no-store").build();
      }
      // Keep provenance locks before fresh human/native-user locks. Never refresh old CAS/body.
      var current = protectedSelf
          ? ProtectedAccountOperations.emailStart(session, authorization, target, humanHeader).current()
          : new MaintenanceTarget(session, authorization, mappings).readOtpSelfEmailStart(target, policy, humanHeader);
      if (delivery.expiresAt <= java.time.Instant.now().getEpochSecond()) deny();
      var binding = parse(delivery.bindingJson);
      if (phase == EmailPhase.CLAIM) {
        if (!"READY".equals(delivery.state)) deny();
        invoke(session, authorization, username, account, current, request,
            ignored -> Response.accepted().build(), binding, delivery.expiresAt);
        delivery.state = "SENDING";
        em.flush();
        return Response.accepted().build();
      }
      if (!"SENDING".equals(delivery.state)) deny();
      Invocation sent;
      try {
        sent = invoke(session, authorization, username, account, current, request,
            send, binding, delivery.expiresAt);
        if (sent.response().getStatus() != 200) throw new IllegalStateException("Unknown delivery outcome");
        var nativeResult = JSON.valueToTree(sent.response().getEntity());
        fields(nativeResult, "info");
        text(nativeResult, "info", 512, false);
        var outcome = JSON.createObjectNode();
        outcome.put("realmId", realm.getId());
        outcome.put("accountId", account);
        outcome.put("operationId", request.operationId());
        outcome.put("operation", "otp.email-start");
        outcome.put("ownerClient", machine.clientId());
        outcome.put("ownerSubject", machine.subject());
        outcome.put("intentDigest", digest);
        outcome.put("previousState", request.expectedState());
        outcome.set("tenantId", request.target().path("tenantId"));
        outcome.put("originDigest", authorization.mac("otp-origin", request.target().path("origin")));
        outcome.put("status", 200);
        outcome.put("deliveryState", "SENT");
        outcome.put("authorityValidUntil", delivery.expiresAt);
        outcome.put("resultDigest", authorization.mac("otp-result", nativeResult));
        outcome.set("emailCredential", binding);
        var result = JSON.createObjectNode();
        result.put("operationId", request.operationId());
        result.put("accountId", account);
        result.put("status", 200);
        result.put("deliveryState", "SENT");
        result.set("result", nativeResult);
        result.put("receipt", authorization.receipt("otp-operation-receipt", outcome));
        delivery.state = "SENT";
        delivery.finalJson = canonical(result);
        em.flush();
        return Response.ok(result).header("Cache-Control", "no-store").build();
      } catch (RuntimeException unknown) {
        // SENDING was committed separately before any SMTP. Unknown can never authorize resend.
        delivery.state = "UNKNOWN";
        delivery.finalJson = null;
        em.flush();
        return Response.status(503).entity(Map.of("error", "OTP delivery outcome is unknown"))
            .header("Cache-Control", "no-store").build();
      }
    }
    if (delivery != null || phase != EmailPhase.REQUEST) deny();
    var protectedCurrent = protectedSelf
        ? ProtectedAccountOperations.emailStart(session, authorization, target, humanHeader) : null;
    var current = protectedSelf ? protectedCurrent.current()
        : new MaintenanceTarget(session, authorization, mappings).readOtpSelfEmailStart(target, policy, humanHeader);
    if (!LifecycleAuthorization.equal(request.expectedState(), current.path("state").asText()))
      throw new jakarta.ws.rs.ClientErrorException("Current OTP target state conflicts", 409);
    long humanValidUntil = protectedSelf ? protectedCurrent.humanValidUntil()
        : policy.requireSelfOtpEmailStart(session, target, humanHeader).identity().validatedJwtExpiresAt();
    var machineToken = machine.nativeAuth().getToken();
    long now = java.time.Instant.now().getEpochSecond();
    if (machineToken.getIat() == null || machineToken.getExp() == null
        || machineToken.getIat() <= 0 || machineToken.getExp() <= machineToken.getIat()
        || machineToken.getExp() <= now) deny();
    long expiry = Math.min(request.body().path("authorityValidUntil").longValue(),
        Math.min(Math.min(humanValidUntil, machineToken.getExp()), now + 600));
    if (expiry <= now) deny();
    var invocation = invoke(session, authorization, username, account, current, request, prepare);
    if (invocation.response().getStatus() != 202 || invocation.emailCredential() == null) deny();
    var nativeResult = JSON.valueToTree(invocation.response().getEntity());
    fields(nativeResult, "info");
    text(nativeResult, "info", 512, false);
    var outcome = JSON.createObjectNode();
    outcome.put("realmId", realm.getId());
    outcome.put("accountId", account);
    outcome.put("operationId", request.operationId());
    outcome.put("operation", "otp.email-start");
    outcome.put("ownerClient", machine.clientId());
    outcome.put("ownerSubject", machine.subject());
    outcome.put("intentDigest", digest);
    outcome.put("previousState", request.expectedState());
    outcome.set("tenantId", request.target().path("tenantId"));
    outcome.put("originDigest", authorization.mac("otp-origin", request.target().path("origin")));
    outcome.put("status", 202);
    outcome.put("deliveryState", "READY");
    outcome.put("authorityValidUntil", expiry);
    outcome.put("resultDigest", authorization.mac("otp-result", nativeResult));
    outcome.set("emailCredential", invocation.emailCredential());
    var result = JSON.createObjectNode();
    result.put("operationId", request.operationId());
    result.put("accountId", account);
    result.put("status", 202);
    result.put("deliveryState", "READY");
    result.set("result", nativeResult);
    result.put("receipt", authorization.receipt("otp-operation-receipt", outcome));
    var saved = new AccountMaintenanceOperation();
    saved.id = id;
    saved.realmId = realm.getId();
    saved.operationId = request.operationId();
    saved.accountId = account;
    saved.command = "otp.email-start";
    saved.ownerClient = machine.clientId();
    saved.ownerSubject = machine.subject();
    saved.intentDigest = digest;
    saved.expectedState = request.expectedState();
    saved.resultJson = canonical(result);
    em.persist(saved);
    delivery = new OtpEmailDelivery();
    delivery.id = id;
    delivery.realmId = realm.getId();
    delivery.accountId = account;
    delivery.intentDigest = digest;
    delivery.bindingJson = canonical(invocation.emailCredential());
    delivery.incarnationDigest = invocation.emailIncarnation();
    delivery.originWorkflowId = uuid(text(request.target().path("origin"), "workflowId", 36, false));
    delivery.expiresAt = expiry;
    delivery.state = "READY";
    em.persist(delivery);
    // Native inactive credential, immutable READY receipt and delivery ownership commit together.
    // No old VerifiedOtpTarget or request-bound grant escapes this callback.
    em.flush();
    enlistForegroundEmail(session, authorization, mappings, policies, username, raw,
        proofHeader, humanHeader, send);
    return Response.status(202).entity(result).header("Cache-Control", "no-store").build();
  }

  private static void enlistForegroundEmail(KeycloakSession owner, LifecycleAuthorization authorization,
      Map<String, Set<String>> mappings, Function<KeycloakSession, GeneralPolicy> policies, String username, byte[] raw,
      String proof, String human, Function<VerifiedOtpTarget, Response> send) {
    var factory = owner.getKeycloakSessionFactory();
    String realmId = owner.getContext().getRealm().getId();
    var actualRequest = owner.getContext().getHttpRequest();
    var actualConnection = owner.getContext().getConnection();
    byte[] frozenRaw = raw.clone();
    owner.getTransactionManager().enlistAfterCompletion(new AbstractKeycloakTransaction() {
      protected void rollbackImpl() {}
      protected void commitImpl() {
        var claimed = new java.util.concurrent.atomic.AtomicBoolean(false);
        try {
          org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction(factory, fresh -> {
            fresh.getContext().setRealm(fresh.realms().getRealm(realmId));
            fresh.getContext().setHttpRequest(actualRequest);
            fresh.getContext().setConnection(actualConnection);
            checkedSelfEmailStart(fresh, authorization, mappings, policies, username, frozenRaw,
                proof, human, null, send, EmailPhase.CLAIM);
            fresh.getTransactionManager().enlistAfterCompletion(new AbstractKeycloakTransaction() {
              protected void commitImpl() { claimed.set(true); }
              protected void rollbackImpl() { claimed.set(false); }
            });
          });
          if (!claimed.get()) return;
          org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction(factory, fresh -> {
            fresh.getContext().setRealm(fresh.realms().getRealm(realmId));
            fresh.getContext().setHttpRequest(actualRequest);
            fresh.getContext().setConnection(actualConnection);
            checkedSelfEmailStart(fresh, authorization, mappings, policies, username, frozenRaw,
                proof, human, null, send, EmailPhase.SEND);
          });
        } catch (RuntimeException refusedOrUnknown) {
          // No raw provider exception, JWT, address or code leaves the foreground callback.
          // READY may recover under a new real request. SENDING/UNKNOWN never automatically send.
        }
      }
    });
  }

  record LinkedEmailStart(String operationId, JsonNode binding, String incarnationDigest) {}

  private static LinkedEmailStart requireLinkedEmailStart(
      jakarta.persistence.EntityManager em, RealmModel realm, LifecycleAuthorization authorization,
      LifecycleAuthorization.CheckedMachine machine, ScopedOtpRequest request) {
    String operation = uuid(text(request.body(), "emailStartOperationId", 36, false));
    String id = realm.getId() + ":" + operation;
    var start = em.find(AccountMaintenanceOperation.class, id, jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
    var delivery = em.find(OtpEmailDelivery.class, id, jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
    if (start == null || delivery == null) throw linkedConflict();
    em.refresh(start); em.refresh(delivery);
    if (!realm.getId().equals(start.realmId) || !realm.getId().equals(delivery.realmId)
        || !request.accountId().equals(start.accountId) || !request.accountId().equals(delivery.accountId)
        || !operation.equals(start.operationId) || !"otp.email-start".equals(start.command)
        || !machine.clientId().equals(start.ownerClient) || !machine.subject().equals(start.ownerSubject)
        || !LifecycleAuthorization.equal(start.intentDigest, delivery.intentDigest)
        || !"SENT".equals(delivery.state) || delivery.finalJson == null
        || delivery.incarnationDigest == null || !delivery.incarnationDigest.matches("[a-f0-9]{64}")
        || delivery.originWorkflowId == null)
      throw linkedConflict();
    var binding = parse(delivery.bindingJson);
    fields(binding, "credentialId", "generation", "destinationDigest");
    uuid(text(binding, "credentialId", 36, false));
    hex(text(binding, "generation", 64, false)); hex(text(binding, "destinationDigest", 64, false));
    var result = parse(delivery.finalJson);
    fields(result, "operationId", "accountId", "status", "deliveryState", "result", "receipt");
    if (!operation.equals(text(result, "operationId", 36, false))
        || !request.accountId().equals(text(result, "accountId", 36, false))
        || !result.path("status").isIntegralNumber() || result.path("status").intValue() != 200
        || !"SENT".equals(text(result, "deliveryState", 16, false))) throw linkedConflict();
    var nativeResult = result.path("result"); fields(nativeResult, "info");
    if (!"OTP mail sent".equals(text(nativeResult, "info", 512, false))) throw linkedConflict();
    var origin = request.target().path("origin").deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode) origin).put("workflowId", uuid(delivery.originWorkflowId));
    var expected = JSON.createObjectNode();
    expected.put("realmId", realm.getId()); expected.put("accountId", request.accountId());
    expected.put("operationId", operation); expected.put("operation", "otp.email-start");
    expected.put("ownerClient", machine.clientId()); expected.put("ownerSubject", machine.subject());
    expected.put("intentDigest", start.intentDigest); expected.put("previousState", start.expectedState);
    expected.set("tenantId", request.target().path("tenantId"));
    expected.put("originDigest", authorization.mac("otp-origin", origin)); expected.put("status", 200);
    expected.put("deliveryState", "SENT"); expected.put("authorityValidUntil", delivery.expiresAt);
    expected.put("resultDigest", authorization.mac("otp-result", nativeResult)); expected.set("emailCredential", binding);
    if (!LifecycleAuthorization.equal(text(result, "receipt", 8192, false),
        authorization.receipt("otp-operation-receipt", expected))) throw linkedConflict();
    return new LinkedEmailStart(operation, binding.deepCopy(), delivery.incarnationDigest);
  }

  private static jakarta.ws.rs.ClientErrorException linkedConflict() {
    return new jakarta.ws.rs.ClientErrorException("Linked OTP workflow conflicts", 409);
  }

  record Invocation(Response response, JsonNode emailCredential, String emailIncarnation) {}

  static Invocation invoke(KeycloakSession session, LifecycleAuthorization authorization,
      String username, String account,
      com.fasterxml.jackson.databind.JsonNode current, ScopedOtpRequest request,
      Function<VerifiedOtpTarget, Response> action) {
    return invoke(session, authorization, username, account, current, request, action, null, 0, null);
  }

  static Invocation invoke(KeycloakSession session, LifecycleAuthorization authorization,
      String username, String account, JsonNode current, ScopedOtpRequest request,
      Function<VerifiedOtpTarget, Response> action, LinkedEmailStart linked) {
    return invoke(session, authorization, username, account, current, request, action, null, 0, linked);
  }

  static Invocation invoke(KeycloakSession session, LifecycleAuthorization authorization,
      String username, String account, JsonNode current, ScopedOtpRequest request,
      Function<VerifiedOtpTarget, Response> action, JsonNode deliveryBinding, long deliveryExpiry) {
    return invoke(session, authorization, username, account, current, request, action, deliveryBinding, deliveryExpiry, null);
  }

  private static Invocation invoke(KeycloakSession session, LifecycleAuthorization authorization,
      String username, String account, JsonNode current, ScopedOtpRequest request,
      Function<VerifiedOtpTarget, Response> action, JsonNode deliveryBinding, long deliveryExpiry,
      LinkedEmailStart linked) {
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
      var checked = new VerifiedOtpTarget(lifetime, authorization, realm, user, request, linked);
      if (deliveryBinding != null) {
        fields(deliveryBinding, "credentialId", "generation", "destinationDigest");
        var selected = user.credentialManager().getStoredCredentialById(
            uuid(text(deliveryBinding, "credentialId", 36, false)));
        checked.bindEmailStartCredential(selected);
        if (!LifecycleAuthorization.equal(canonical(deliveryBinding), canonical(checked.emailCredential))) deny();
        checked.deliveryCredentialId = selected.getId();
        checked.deliveryExpiry = deliveryExpiry;
      }
      var response = action.apply(checked);
      lifetime.check();
      if (response == null) throw new IllegalStateException("OTP callback did not return a response");
      return new Invocation(Response.fromResponse(response).header("Cache-Control", "no-store").build(),
          checked.emailCredential == null ? null : checked.emailCredential.deepCopy(), checked.emailIncarnation);
    } finally {
      lifetime.open = false;
    }
  }

  /** Same live request and transaction only. It contains no human bearer or transferable authority. */
  public static final class VerifiedOtpTarget {
    private final Lifetime lifetime;
    private final LifecycleAuthorization authorization;
    private final RealmModel realm;
    private final UserModel user;
    private final ScopedOtpRequest request;
    private com.fasterxml.jackson.databind.JsonNode emailCredential;
    private String emailIncarnation;
    private final LinkedEmailStart linkedStart;
    private String deliveryCredentialId;
    private long deliveryExpiry;
    private VerifiedOtpTarget(Lifetime lifetime, LifecycleAuthorization authorization,
        RealmModel realm, UserModel user, ScopedOtpRequest request, LinkedEmailStart linkedStart) {
      this.lifetime = lifetime;
      this.authorization = authorization;
      this.realm = realm;
      this.user = user;
      this.request = request;
      this.linkedStart = linkedStart;
    }
    public boolean hasLinkedEmailStart() { lifetime.check(); return linkedStart != null; }
    public KeycloakSession session() { lifetime.check(); return lifetime.session; }
    public RealmModel realm() { lifetime.check(); return realm; }
    public UserModel user() { lifetime.check(); return user; }
    public String initialCode() { lifetime.check(); if (request == null || !Set.of("otp.app-setup", "otp.email-finish").contains(request.operation())) deny(); return request.otp().path("initialCode").textValue(); }
    public String secret() { lifetime.check(); if (request == null || !"otp.app-setup".equals(request.operation())) deny(); return request.otp().path("secret").textValue(); }
    public String email() { lifetime.check(); if (request == null || !"otp.email-start".equals(request.operation())) deny(); return request.otp().path("email").textValue(); }
    public org.keycloak.credential.CredentialModel emailCredentialForDelivery() {
      lifetime.check();
      if (request == null || !"otp.email-start".equals(request.operation()) || deliveryCredentialId == null
          || deliveryExpiry <= java.time.Instant.now().getEpochSecond()) deny();
      var selected = user.credentialManager().getStoredCredentialById(deliveryCredentialId);
      var expected = emailCredential;
      emailCredential = null;
      bindEmailCredential(selected);
      if (!LifecycleAuthorization.equal(canonical(expected), canonical(emailCredential))) deny();
      lifetime.check();
      return selected;
    }
    public void bindEmailStartCredential(org.keycloak.credential.CredentialModel selected) {
      lifetime.check();
      if (request == null || !"otp.email-start".equals(request.operation())) deny();
      bindEmailCredential(selected);
    }
    /** Binds a current native-owned credential before its effect; never accepts DTO authority. */
    public void bindEmailFinishCredential(org.keycloak.credential.CredentialModel selected) {
      lifetime.check();
      if (request == null || !"otp.email-finish".equals(request.operation())
          || emailCredential != null || selected == null) deny();
      bindEmailCredential(selected);
      if (linkedStart != null && (!LifecycleAuthorization.equal(linkedStart.incarnationDigest(), emailIncarnation)
          || !linkedStart.binding().path("credentialId").equals(emailCredential.path("credentialId"))
          || !linkedStart.binding().path("destinationDigest").equals(emailCredential.path("destinationDigest"))))
        throw linkedConflict();
    }
    private void bindEmailCredential(org.keycloak.credential.CredentialModel selected) {
      lifetime.check();
      if (emailCredential != null || selected == null) deny();
      String id = uuid(selected.getId());
      var owned = user.credentialManager().getStoredCredentialById(id);
      if (owned == null || !"MAIL_OTP_CM".equals(owned.getType())
          || !java.util.Objects.equals(owned.getType(), selected.getType())
          || !java.util.Objects.equals(owned.getCreatedDate(), selected.getCreatedDate())
          || !java.util.Objects.equals(owned.getCredentialData(), selected.getCredentialData())
          || !java.util.Objects.equals(owned.getSecretData(), selected.getSecretData())
          || owned.getCreatedDate() == null || owned.getCreatedDate() <= 0) deny();
      var generation = JSON.createObjectNode();
      generation.put("credentialId", id);
      generation.put("createdDate", owned.getCreatedDate());
      generation.put("credentialData", owned.getCredentialData());
      generation.put("secretData", owned.getSecretData());
      String destination = text(parse(owned.getCredentialData()), "email", 320, false);
      var binding = JSON.createObjectNode();
      binding.put("credentialId", id);
      binding.put("generation", authorization.mac("otp-email-credential-generation", generation));
      binding.put("destinationDigest", authorization.mac("otp-email-destination", JSON.valueToTree(destination)));
      emailCredential = binding;
      var data = parse(owned.getCredentialData());
      var allowed = Set.of("ttlInSeconds", "email", "failedVerifications", "active", "mailsSentAt", "lockedUntil", "lockoutLevel");
      var names = new java.util.HashSet<String>(); data.fieldNames().forEachRemaining(names::add);
      if (!allowed.containsAll(names) || !names.containsAll(Set.of("ttlInSeconds", "email", "failedVerifications", "active"))
          || !data.path("ttlInSeconds").isIntegralNumber() || data.path("ttlInSeconds").longValue() <= 0
          || !data.path("failedVerifications").isIntegralNumber() || data.path("failedVerifications").longValue() < 0
          || !data.path("active").isBoolean()) deny();
      var immutable = (com.fasterxml.jackson.databind.node.ObjectNode) data.deepCopy();
      immutable.remove("failedVerifications"); immutable.remove("active");
      var incarnation = JSON.createObjectNode();
      incarnation.put("credentialId", id); incarnation.put("createdDate", owned.getCreatedDate());
      incarnation.set("credentialData", immutable); incarnation.set("secretData", parse(owned.getSecretData()));
      emailIncarnation = authorization.mac("otp-email-credential-incarnation", incarnation);
      lifetime.check();
    }
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
