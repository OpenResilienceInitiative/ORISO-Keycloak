package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.Set;
import java.util.function.Function;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.RealmEntity;

/** Finite pending-recipient provenance. A body/proof alone never selects an active account. */
final class ProtectedOtpBootstrap {
  private ProtectedOtpBootstrap() {}

  static Response prepare(KeycloakSession session, LifecycleAuthorization crypto,
      LifecycleAuthorization.CheckedMachine authenticatedMachine, String username, JsonNode target,
      Function<UserModel, Response> read) {
    fields(target, "accountId", "tenantId", "bootstrap");
    String account = uuid(text(target, "accountId", 36, false));
    String tenant = text(target, "tenantId", 20, false);
    if (!tenant.matches("0|[1-9][0-9]{0,18}")) bad();
    var value = target.path("bootstrap");
    fields(value, "v", "kind", "approvalId", "scopeDigest", "authorizationRevision",
        "acceptanceClaim", "attemptId", "execution", "creationFingerprint", "creationProof",
        "authorityValidUntil");
    if (number(value, "v", true) != 1
        || !"PROTECTED_ACCEPTANCE".equals(text(value, "kind", 30, false))) deny();
    String approval = uuid(text(value, "approvalId", 36, false));
    String attemptId = uuid(text(value, "attemptId", 36, false));
    String scopeDigest = text(value, "scopeDigest", 64, false); hex(scopeDigest);
    String fingerprint = text(value, "creationFingerprint", 64, false); hex(fingerprint);
    String creationProof = text(value, "creationProof", 16384, false);
    long revision = number(value, "authorizationRevision", true);
    long assertedDeadline = number(value, "authorityValidUntil", true);
    var claim = value.path("acceptanceClaim");
    fields(claim, "workflowId", "inviteId", "authorizationRevision", "claimId", "journalVersion");
    String claimId = uuid(text(claim, "claimId", 36, false));
    uuid(text(claim, "workflowId", 36, false)); text(claim, "inviteId", 255, false);
    if (number(claim, "journalVersion", true) != 1
        || number(claim, "authorizationRevision", true) != revision) deny();
    var execution = value.path("execution");
    fields(execution, "executionId", "generation");
    String executionId = uuid(text(execution, "executionId", 36, false));
    if (number(execution, "generation", false) != 0) conflict();

    var config = ProtectedInvitationFactory.checkedBootstrapConfiguration(session);
    var realm = session.getContext().getRealm();
    if (!config.realmId.equals(realm.getId()) || !config.realmName.equals(realm.getName())
        || !crypto.creatorSubject.equals(config.actors.get("ACCOUNT_CREATE"))
        || !crypto.adminSubject.equals(config.actors.get("ACCOUNT_ADMIN"))) deny();
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var lockedRealm = em.find(RealmEntity.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
    if (lockedRealm == null) deny();
    em.refresh(lockedRealm);
    var approvalRow = em.find(ProtectedInvitationApproval.class,
        ProtectedInvitationResource.key(realm.getId(), approval), LockModeType.PESSIMISTIC_WRITE);
    if (approvalRow == null) deny();
    em.refresh(approvalRow);
    var attempt = em.find(AccountLifecycleAttempt.class,
        ProtectedInvitationResource.protectedAttemptKey(realm.getId(), approval, attemptId),
        LockModeType.PESSIMISTIC_WRITE);
    if (attempt == null) deny();
    em.refresh(attempt);
    // Fresh native machine grants are checked after the provenance locks, never inferred from DTOs.
    var machine = new ProtectedInvitationAuthorization(config, crypto)
        .requireMachine(session, Set.of("ACCOUNT_ADMIN"));
    if (!authenticatedMachine.clientId().equals(machine.clientId())
        || !authenticatedMachine.subject().equals(machine.subject())) deny();
    if (!"BOUND".equals(approvalRow.state) || !attemptId.equals(approvalRow.boundAttemptId)
        || !realm.getId().equals(approvalRow.realmId) || !approval.equals(approvalRow.approvalId)
        || !LifecycleAuthorization.equal(scopeDigest, approvalRow.scopeDigest)
        || revision != approvalRow.authorizationRevision
        || !approvalRow.workflowId.equals(claim.path("workflowId").asText())
        || !approvalRow.inviteId.equals(claim.path("inviteId").asText())) deny();
    if (!"OPEN".equals(attempt.state) || attempt.generation != 0 || attempt.terminalOperation != null
        || !attemptId.equals(attempt.attemptId) || !realm.getId().equals(attempt.realmId)
        || !account.equals(attempt.accountId) || !executionId.equals(attempt.executionId)
        || !executionId.equals(attempt.createExecution)
        || !"backend-account-create".equals(attempt.ownerClient)
        || !config.actors.get("ACCOUNT_CREATE").equals(attempt.ownerSubject)
        || !LifecycleAuthorization.equal(fingerprint, attempt.creationFingerprint)
        || !LifecycleAuthorization.equal(creationProof, attempt.creationProof)) conflict();
    var scope = parse(attempt.scope);
    var approvalBinding = scope.path("approvalBinding");
    if (!tenant.equals(scope.path("tenantId").asText())
        || !approval.equals(approvalBinding.path("approvalId").asText())
        || !scopeDigest.equals(approvalBinding.path("scopeDigest").asText())
        || revision != approvalBinding.path("authorizationRevision").asLong(-1)
        || !canonical(claim).equals(canonical(approvalBinding.path("acceptanceClaim")))) deny();
    var frozenProfile = parse(approvalRow.scope).path("profile");
    var profile = config.profiles.get(text(frozenProfile, "id", 255, false));
    if (profile == null || !canonical(frozenProfile).equals(canonical(profile.snapshot()))
        || !attempt.groupId.equals(profile.groupId())
        || !attempt.roleFingerprint.equals(crypto.mac("protected-initial-profile/v1", frozenProfile))) deny();
    config.validateProfile(session, profile);

    String id = "bootstrap:" + crypto.mac("otp-bootstrap-row/v1", JSON.valueToTree(attempt.id));
    var prior = em.find(ProtectedOtpBootstrapState.class, id, LockModeType.PESSIMISTIC_WRITE);
    if (prior != null) em.refresh(prior);
    String originDigest = crypto.mac("otp-bootstrap-origin/v1", target);
    long now = Instant.now().getEpochSecond();
    var token = machine.nativeAuth().getToken();
    if (token.getIat() == null || token.getExp() == null || token.getIat() <= 0
        || token.getExp() <= token.getIat() || token.getExp() <= now) deny();
    long deadline = Math.min(assertedDeadline,
        Math.min(token.getExp(), Instant.parse(approvalRow.validUntil).getEpochSecond()));
    if (prior != null) {
      if (!realm.getId().equals(prior.realmId) || !approval.equals(prior.approvalId)
          || !attemptId.equals(prior.attemptId) || !account.equals(prior.accountId)
          || !claimId.equals(prior.claimId) || !executionId.equals(prior.executionId)
          || !machine.clientId().equals(prior.ownerClient) || !machine.subject().equals(prior.ownerSubject)
          || !LifecycleAuthorization.equal(originDigest, prior.originDigest)
          || !"PREPARED".equals(prior.state)) conflict();
      deadline = Math.min(deadline, prior.authorityValidUntil);
    }
    // Exact PREPARED replay keeps its historical receipt bound; current machine and invitation
    // provenance still authorize this read. A new preparation must have a live asserted deadline.
    if (!Instant.parse(approvalRow.validUntil).isAfter(Instant.now())
        || prior == null && deadline <= now) deny();
    if (realm.getComponentsStream(realm.getId(), "org.keycloak.storage.UserStorageProvider")
        .findAny().isPresent()) deny();
    var snapshot = AccountLifecycleResource.lockedSnapshot(em, account);
    if (!realm.getId().equals(snapshot.path("realmId").asText())
        || !username.equals(snapshot.path("username").asText())
        || snapshot.path("enabled").asBoolean()
        || !LifecycleAuthorization.equal(attempt.profileFingerprint, crypto.mac("pending-profile", snapshot))) conflict();
    var user = session.users().getUserById(realm, account);
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) { cache.evict(realm, user); user = session.users().getUserById(realm, account); }
    if (user == null || user.isEnabled()) conflict();
    var result = read.apply(user);
    if (result == null || result.getStatus() != 200) throw new IllegalStateException("Pending OTP prepare unavailable");
    if (prior == null) {
      prior = new ProtectedOtpBootstrapState();
      prior.id = id; prior.realmId = realm.getId(); prior.approvalId = approval;
      prior.attemptId = attemptId; prior.accountId = account; prior.claimId = claimId;
      prior.executionId = executionId; prior.ownerClient = machine.clientId();
      prior.ownerSubject = machine.subject(); prior.originDigest = originDigest;
      prior.authorityValidUntil = deadline; prior.state = "PREPARED";
      var receipt = JSON.createObjectNode();
      receipt.put("v", 1); receipt.put("realmId", prior.realmId); receipt.put("approvalId", approval);
      receipt.put("attemptId", attemptId); receipt.put("accountId", account); receipt.put("claimId", claimId);
      receipt.put("executionId", executionId); receipt.put("bootstrapIncarnation", executionId);
      receipt.put("ownerClient", prior.ownerClient); receipt.put("ownerSubject", prior.ownerSubject);
      receipt.put("originDigest", originDigest); receipt.put("authorityValidUntil", deadline);
      receipt.put("state", "PREPARED");
      prior.prepareReceipt = crypto.receipt("otp-bootstrap-prepare/v1", receipt);
      em.persist(prior);
    }
    em.flush();
    var response = JSON.createObjectNode();
    response.set("otpInfo", JSON.valueToTree(result.getEntity()));
    response.put("bootstrapReceipt", prior.prepareReceipt);
    response.put("authorityValidUntil", prior.authorityValidUntil);
    return Response.ok(response).header("Cache-Control", "no-store").build();
  }

  static Response app(KeycloakSession session, LifecycleAuthorization crypto,
      LifecycleAuthorization.CheckedMachine authenticatedMachine, String username,
      ScopedOtpRequest request, JsonNode materialized, String prepareReceipt,
      Function<UserModel, Response> effect) {
    if (prepareReceipt == null || prepareReceipt.length() > 8192) deny();
    var parts = prepareReceipt.split("\\.", -1);
    if (parts.length != 2 || !parts[0].matches("[A-Za-z0-9_-]+")
        || !parts[1].matches("[0-9a-f]{64}")) deny();
    JsonNode receipt;
    try { receipt = parse(java.util.Base64.getUrlDecoder().decode(parts[0])); }
    catch (IllegalArgumentException rejected) { deny(); return null; }
    fields(receipt, "v", "realmId", "approvalId", "attemptId", "accountId", "claimId",
        "executionId", "bootstrapIncarnation", "ownerClient", "ownerSubject", "originDigest",
        "authorityValidUntil", "state");
    if (!LifecycleAuthorization.equal(prepareReceipt, crypto.receipt("otp-bootstrap-prepare/v1", receipt))
        || number(receipt, "v", true) != 1 || !"PREPARED".equals(receipt.path("state").asText())
        || !LifecycleAuthorization.equal(request.expectedState(),
            crypto.mac("otp-bootstrap-state/v1", JSON.valueToTree(prepareReceipt)))) deny();
    var realm = session.getContext().getRealm();
    String account = request.accountId();
    String approval = uuid(text(receipt, "approvalId", 36, false));
    String attemptId = uuid(text(receipt, "attemptId", 36, false));
    var config = ProtectedInvitationFactory.checkedBootstrapConfiguration(session);
    if (!realm.getId().equals(receipt.path("realmId").asText())
        || !account.equals(receipt.path("accountId").asText())
        || !"INVITATION".equals(request.target().path("origin").path("kind").asText())) deny();
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var lockedRealm = em.find(RealmEntity.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
    if (lockedRealm == null) deny(); em.refresh(lockedRealm);
    var approved = em.find(ProtectedInvitationApproval.class,
        ProtectedInvitationResource.key(realm.getId(), approval), LockModeType.PESSIMISTIC_WRITE);
    if (approved == null) deny(); em.refresh(approved);
    var attempt = em.find(AccountLifecycleAttempt.class,
        ProtectedInvitationResource.protectedAttemptKey(realm.getId(), approval, attemptId),
        LockModeType.PESSIMISTIC_WRITE);
    if (attempt == null) deny(); em.refresh(attempt);
    var machine = new ProtectedInvitationAuthorization(config, crypto)
        .requireMachine(session, Set.of("ACCOUNT_ADMIN"));
    if (!authenticatedMachine.clientId().equals(machine.clientId())
        || !authenticatedMachine.subject().equals(machine.subject())) deny();
    String rowId = "bootstrap:" + crypto.mac("otp-bootstrap-row/v1", JSON.valueToTree(attempt.id));
    var bootstrap = em.find(ProtectedOtpBootstrapState.class, rowId, LockModeType.PESSIMISTIC_WRITE);
    if (bootstrap == null) deny(); em.refresh(bootstrap);
    if (!LifecycleAuthorization.equal(prepareReceipt, bootstrap.prepareReceipt)
        || !realm.getId().equals(bootstrap.realmId) || !approval.equals(bootstrap.approvalId)
        || !attemptId.equals(bootstrap.attemptId) || !account.equals(bootstrap.accountId)
        || !machine.clientId().equals(bootstrap.ownerClient) || !machine.subject().equals(bootstrap.ownerSubject)
        || !"BOUND".equals(approved.state) || !attemptId.equals(approved.boundAttemptId)
        || !"OPEN".equals(attempt.state) || attempt.generation != 0 || attempt.terminalOperation != null
        || !account.equals(attempt.accountId) || !bootstrap.executionId.equals(attempt.executionId)
        || !bootstrap.executionId.equals(attempt.createExecution)
        || !"backend-account-create".equals(attempt.ownerClient)
        || !config.actors.get("ACCOUNT_CREATE").equals(attempt.ownerSubject)
        || !approved.workflowId.equals(request.target().path("origin").path("workflowId").asText())) conflict();
    var scope = parse(attempt.scope);
    if (!request.target().path("tenantId").equals(scope.path("tenantId"))
        || !bootstrap.claimId.equals(scope.path("approvalBinding").path("acceptanceClaim").path("claimId").asText())) deny();
    String id = realm.getId() + ":" + request.operationId();
    String digest = crypto.mac("otp-bootstrap-intent/v1", materialized);
    var prior = em.find(AccountMaintenanceOperation.class, id, LockModeType.PESSIMISTIC_WRITE);
    if (prior != null) {
      em.refresh(prior);
      if (!realm.getId().equals(prior.realmId) || !account.equals(prior.accountId)
          || !"otp.bootstrap-app-setup".equals(prior.command)
          || !machine.clientId().equals(prior.ownerClient) || !machine.subject().equals(prior.ownerSubject)
          || !LifecycleAuthorization.equal(digest, prior.intentDigest)
          || !LifecycleAuthorization.equal(request.expectedState(), prior.expectedState)) conflict();
      var saved = parse(prior.resultJson);
      int status = saved.path("status").asInt();
      if (!Set.of(201, 401).contains(status)) deny();
      return Response.status(status).entity(saved).header("Cache-Control", "no-store").build();
    }
    if (!"PREPARED".equals(bootstrap.state)) conflict();
    // Preparation expiry describes that earlier machine request, not the recipient's live workflow.
    // This command has its own fresh canonical machine authentication and short bound proof.
    if (!Instant.parse(approved.validUntil).isAfter(Instant.now())) deny();
    var frozenProfile = parse(approved.scope).path("profile");
    var profile = config.profiles.get(text(frozenProfile, "id", 255, false));
    if (profile == null || !canonical(frozenProfile).equals(canonical(profile.snapshot()))
        || !attempt.groupId.equals(profile.groupId())
        || !attempt.roleFingerprint.equals(crypto.mac("protected-initial-profile/v1", frozenProfile))) deny();
    config.validateProfile(session, profile);
    if (realm.getComponentsStream(realm.getId(), "org.keycloak.storage.UserStorageProvider").findAny().isPresent()) deny();
    var snapshot = AccountLifecycleResource.lockedSnapshot(em, account);
    if (!realm.getId().equals(snapshot.path("realmId").asText())
        || !username.equals(snapshot.path("username").asText()) || snapshot.path("enabled").asBoolean()
        || !LifecycleAuthorization.equal(attempt.profileFingerprint, crypto.mac("pending-profile", snapshot))) conflict();
    var user = session.users().getUserById(realm, account);
    if (user == null || user.isEnabled()) conflict();
    var response = effect.apply(user);
    if (response == null || !Set.of(201, 401).contains(response.getStatus()))
      throw new IllegalStateException("Unsupported pending OTP outcome");
    int status = response.getStatus();
    var nativeResult = JSON.valueToTree(response.getEntity());
    if (status == 201) { fields(nativeResult, "info"); text(nativeResult, "info", 512, false); }
    else { fields(nativeResult, "error", "error_description");
      text(nativeResult, "error", 100, false); text(nativeResult, "error_description", 512, false); }
    var outcome = receipt.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode) outcome).put("state", status == 201 ? "COMPLETE" : "INVALID");
    ((com.fasterxml.jackson.databind.node.ObjectNode) outcome).put("operationId", request.operationId());
    ((com.fasterxml.jackson.databind.node.ObjectNode) outcome).put("intentDigest", digest);
    ((com.fasterxml.jackson.databind.node.ObjectNode) outcome).put("status", status);
    ((com.fasterxml.jackson.databind.node.ObjectNode) outcome).put("resultDigest", crypto.mac("otp-result", nativeResult));
    var result = JSON.createObjectNode(); result.put("status", status); result.set("result", nativeResult);
    result.put("receipt", crypto.receipt("otp-bootstrap-complete/v1", outcome));
    var saved = new AccountMaintenanceOperation(); saved.id = id; saved.realmId = realm.getId();
    saved.operationId = request.operationId(); saved.accountId = account; saved.command = "otp.bootstrap-app-setup";
    saved.ownerClient = machine.clientId(); saved.ownerSubject = machine.subject(); saved.intentDigest = digest;
    saved.expectedState = request.expectedState(); saved.resultJson = canonical(result); em.persist(saved);
    if (status == 201) {
      bootstrap.state = "COMPLETE";
      em.flush();
      // Only this exact typed successful bootstrap may advance the pending credential snapshot.
      attempt.profileFingerprint = crypto.mac("pending-profile", AccountLifecycleResource.lockedSnapshot(em, account));
    }
    em.flush();
    return Response.status(status).entity(result).header("Cache-Control", "no-store").build();
  }

  private enum EmailPhase { REQUEST, CLAIM, SEND }

  static Response emailStart(KeycloakSession session, LifecycleAuthorization crypto,
      String username, byte[] raw, String proof, String human, String prepareReceipt,
      Function<ScopedOtpAccess.VerifiedOtpTarget, Response> prepare,
      Function<ScopedOtpAccess.VerifiedOtpTarget, Response> send) {
    return emailStart(session, crypto, username, raw, proof, human, prepareReceipt, prepare, send, EmailPhase.REQUEST);
  }

  private static Response emailStart(KeycloakSession session, LifecycleAuthorization crypto,
      String username, byte[] raw, String proof, String human, String prepareReceipt,
      Function<ScopedOtpAccess.VerifiedOtpTarget, Response> prepare,
      Function<ScopedOtpAccess.VerifiedOtpTarget, Response> send, EmailPhase phase) {
    var machine = crypto.requireMachine(session, "ACCOUNT_ADMIN");
    if (human != null || username == null || username.isBlank() || username.length() > 255
        || username.chars().anyMatch(c -> c < 32 || c == 127)) deny();
    var body = parse(raw);
    String account = uuid(text(body.path("target"), "accountId", 36, false));
    var request = ScopedOtpRequest.parse("otp.email-start", account, body);
    var materialized = body.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode) materialized).put("username", username);
    ((com.fasterxml.jackson.databind.node.ObjectNode) materialized).put("bootstrapReceipt", prepareReceipt);
    crypto.verifyCommand(proof, machine, "oriso-otp", "OTP", "otp.bootstrap-email-start", "PUT",
        "realm/" + session.getContext().getRealm().getId() + "/account/" + account, materialized);
    var owner = emailOwner(session, crypto, machine, request, prepareReceipt);
    crypto.verifyCommand(proof, machine, "oriso-otp", "OTP", "otp.bootstrap-email-start", "PUT",
        "realm/" + owner.realm().getId() + "/account/" + account, materialized);
    String id = owner.realm().getId() + ":" + request.operationId();
    String digest = crypto.mac("otp-bootstrap-intent/v1", materialized);
    var prior = owner.em().find(AccountMaintenanceOperation.class, id, LockModeType.PESSIMISTIC_WRITE);
    var delivery = owner.em().find(OtpEmailDelivery.class, id, LockModeType.PESSIMISTIC_WRITE);
    if (prior != null) {
      owner.em().refresh(prior);
      if (!account.equals(prior.accountId) || !owner.realm().getId().equals(prior.realmId)
          || !"otp.bootstrap-email-start".equals(prior.command)
          || !machine.clientId().equals(prior.ownerClient) || !machine.subject().equals(prior.ownerSubject)
          || !LifecycleAuthorization.equal(digest, prior.intentDigest)
          || !LifecycleAuthorization.equal(request.expectedState(), prior.expectedState)
          || delivery == null) conflict();
      owner.em().refresh(delivery);
      if (!owner.realm().getId().equals(delivery.realmId) || !account.equals(delivery.accountId)
          || !LifecycleAuthorization.equal(digest, delivery.intentDigest)) deny();
      if (phase == EmailPhase.REQUEST && "SENT".equals(delivery.state) && delivery.finalJson != null)
        return Response.ok(parse(delivery.finalJson)).header("Cache-Control", "no-store").build();
      if (delivery.expiresAt <= Instant.now().getEpochSecond())
        throw new jakarta.ws.rs.ServiceUnavailableException("OTP delivery outcome is unavailable");
      var user = currentEmailUser(session, crypto, owner, username, true);
      var binding = parse(delivery.bindingJson);
      var projection = JSON.createObjectNode().put("username", username);
      if (phase == EmailPhase.REQUEST) {
        if (!"READY".equals(delivery.state))
          throw new jakarta.ws.rs.ServiceUnavailableException("OTP delivery outcome is unknown");
        enlistEmail(session, crypto, username, raw, proof, prepareReceipt, send);
        return Response.status(202).entity(parse(prior.resultJson)).header("Cache-Control", "no-store").build();
      }
      if (phase == EmailPhase.CLAIM) {
        if (!"READY".equals(delivery.state)) deny();
        ScopedOtpAccess.invoke(session, crypto, username, account, projection, request,
            ignored -> Response.accepted().build(), binding, delivery.expiresAt);
        delivery.state = "SENDING";
        owner.em().flush();
        return Response.accepted().build();
      }
      if (!"SENDING".equals(delivery.state)) deny();
      try {
        var sent = ScopedOtpAccess.invoke(session, crypto, username, account, projection, request,
            send, binding, delivery.expiresAt);
        if (sent.response().getStatus() != 200) throw new IllegalStateException("Unknown OTP delivery");
        var result = emailResult(crypto, owner, request.operationId(), digest, delivery.expiresAt, binding,
            JSON.valueToTree(sent.response().getEntity()), 200, "SENT");
        delivery.state = "SENT"; delivery.finalJson = canonical(result);
        owner.em().flush();
        return Response.ok(result).header("Cache-Control", "no-store").build();
      } catch (RuntimeException unknown) {
        delivery.state = "UNKNOWN"; delivery.finalJson = null;
        owner.em().flush();
        return Response.status(503).entity(java.util.Map.of("error", "OTP delivery outcome is unknown"))
            .header("Cache-Control", "no-store").build();
      }
    }
    if (delivery != null || phase != EmailPhase.REQUEST || !"PREPARED".equals(owner.bootstrap().state)) conflict();
    var user = currentEmailUser(session, crypto, owner, username, false);
    if (!request.otp().path("email").asText().equals(parse(owner.approval().scope).path("scope").path("recipient").asText())) deny();
    var token = machine.nativeAuth().getToken();
    long now = Instant.now().getEpochSecond();
    if (token.getIat() == null || token.getExp() == null || token.getIat() <= 0
        || token.getExp() <= token.getIat() || token.getExp() <= now) deny();
    long expiry = Math.min(number(body, "authorityValidUntil", true),
        Math.min(token.getExp(), Math.min(now + 600, Instant.parse(owner.approval().validUntil).getEpochSecond())));
    if (expiry <= now) deny();
    var projection = JSON.createObjectNode().put("username", username);
    var invocation = ScopedOtpAccess.invoke(session, crypto, username, account, projection, request, prepare);
    if (invocation.response().getStatus() != 202 || invocation.emailCredential() == null) deny();
    var ready = emailResult(crypto, owner, request.operationId(), digest, expiry, invocation.emailCredential(),
        JSON.valueToTree(invocation.response().getEntity()), 202, "READY");
    var saved = new AccountMaintenanceOperation(); saved.id = id; saved.realmId = owner.realm().getId();
    saved.operationId = request.operationId(); saved.accountId = account; saved.command = "otp.bootstrap-email-start";
    saved.ownerClient = machine.clientId(); saved.ownerSubject = machine.subject(); saved.intentDigest = digest;
    saved.expectedState = request.expectedState(); saved.resultJson = canonical(ready); owner.em().persist(saved);
    delivery = new OtpEmailDelivery(); delivery.id = id; delivery.realmId = owner.realm().getId();
    delivery.accountId = account; delivery.intentDigest = digest;
    delivery.bindingJson = canonical(invocation.emailCredential()); delivery.incarnationDigest = invocation.emailIncarnation();
    delivery.originWorkflowId = owner.approval().workflowId; delivery.expiresAt = expiry; delivery.state = "READY";
    owner.em().persist(delivery);
    owner.bootstrap().state = "EMAIL_READY";
    owner.em().flush();
    owner.bootstrap().emailPendingFingerprint = crypto.mac("pending-profile", AccountLifecycleResource.lockedSnapshot(owner.em(), account));
    owner.em().flush();
    enlistEmail(session, crypto, username, raw, proof, prepareReceipt, send);
    return Response.status(202).entity(ready).header("Cache-Control", "no-store").build();
  }

  static Response emailFinish(KeycloakSession session, LifecycleAuthorization crypto,
      String username, byte[] raw, String proof, String human, String prepareReceipt,
      Function<ScopedOtpAccess.VerifiedOtpTarget, Response> finish) {
    var machine = crypto.requireMachine(session, "ACCOUNT_ADMIN");
    if (human != null || username == null || username.isBlank() || username.length() > 255
        || username.chars().anyMatch(c -> c < 32 || c == 127)) deny();
    var body = parse(raw);
    String account = uuid(text(body.path("target"), "accountId", 36, false));
    var request = ScopedOtpRequest.parse("otp.email-finish", account, body);
    String startOperation = uuid(text(body, "emailStartOperationId", 36, false));
    var materialized = body.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode) materialized).put("username", username);
    ((com.fasterxml.jackson.databind.node.ObjectNode) materialized).put("bootstrapReceipt", prepareReceipt);
    crypto.verifyCommand(proof, machine, "oriso-otp", "OTP", "otp.bootstrap-email-finish", "POST",
        "realm/" + session.getContext().getRealm().getId() + "/account/" + account, materialized);
    var owner = emailOwner(session, crypto, machine, request, prepareReceipt);
    crypto.verifyCommand(proof, machine, "oriso-otp", "OTP", "otp.bootstrap-email-finish", "POST",
        "realm/" + owner.realm().getId() + "/account/" + account, materialized);
    String id = owner.realm().getId() + ":" + request.operationId();
    String digest = crypto.mac("otp-bootstrap-intent/v1", materialized);
    var prior = owner.em().find(AccountMaintenanceOperation.class, id, LockModeType.PESSIMISTIC_WRITE);
    if (prior != null) {
      owner.em().refresh(prior);
      if (!owner.realm().getId().equals(prior.realmId) || !account.equals(prior.accountId)
          || !"otp.bootstrap-email-finish".equals(prior.command)
          || !machine.clientId().equals(prior.ownerClient) || !machine.subject().equals(prior.ownerSubject)
          || !LifecycleAuthorization.equal(digest, prior.intentDigest)
          || !LifecycleAuthorization.equal(request.expectedState(), prior.expectedState)) conflict();
      var saved = parse(prior.resultJson);
      int status = saved.path("status").asInt();
      if (!Set.of(201, 401).contains(status)) deny();
      return Response.status(status).entity(saved).header("Cache-Control", "no-store").build();
    }
    if (!"EMAIL_READY".equals(owner.bootstrap().state)) conflict();
    var user = currentEmailUser(session, crypto, owner, username, true);
    String startId = owner.realm().getId() + ":" + startOperation;
    var start = owner.em().find(AccountMaintenanceOperation.class, startId, LockModeType.PESSIMISTIC_WRITE);
    var delivery = owner.em().find(OtpEmailDelivery.class, startId, LockModeType.PESSIMISTIC_WRITE);
    if (start == null || delivery == null) deny();
    owner.em().refresh(start); owner.em().refresh(delivery);
    if (!owner.realm().getId().equals(start.realmId) || !account.equals(start.accountId)
        || !"otp.bootstrap-email-start".equals(start.command) || !startOperation.equals(start.operationId)
        || !machine.clientId().equals(start.ownerClient) || !machine.subject().equals(start.ownerSubject)
        || !LifecycleAuthorization.equal(request.expectedState(), start.expectedState)
        || !owner.realm().getId().equals(delivery.realmId) || !account.equals(delivery.accountId)
        || !owner.approval().workflowId.equals(delivery.originWorkflowId)
        || !LifecycleAuthorization.equal(start.intentDigest, delivery.intentDigest)
        || !"SENT".equals(delivery.state) || delivery.finalJson == null || delivery.incarnationDigest == null) deny();
    var binding = parse(delivery.bindingJson);
    var sent = parse(delivery.finalJson);
    fields(sent, "status", "deliveryState", "result", "receipt");
    var expectedSent = emailResult(crypto, owner, startOperation, start.intentDigest,
        delivery.expiresAt, binding, sent.path("result"), 200, "SENT");
    if (!LifecycleAuthorization.equal(canonical(expectedSent), canonical(sent))) deny();
    var linked = new ScopedOtpAccess.LinkedEmailStart(startOperation, binding.deepCopy(), delivery.incarnationDigest);
    var projection = JSON.createObjectNode().put("username", username);
    var invocation = ScopedOtpAccess.invoke(session, crypto, username, account, projection, request, finish, linked);
    int status = invocation.response().getStatus();
    if (!Set.of(201, 401).contains(status) || invocation.emailCredential() == null) deny();
    var nativeResult = JSON.valueToTree(invocation.response().getEntity());
    if (status == 201) { fields(nativeResult, "info"); text(nativeResult, "info", 512, false); }
    else { fields(nativeResult, "error", "error_description");
      text(nativeResult, "error", 100, false); text(nativeResult, "error_description", 512, false); }
    var facts = (com.fasterxml.jackson.databind.node.ObjectNode) owner.receipt().deepCopy();
    facts.put("state", status == 201 ? "COMPLETE" : "INVALID"); facts.put("operationId", request.operationId());
    facts.put("intentDigest", digest); facts.put("status", status); facts.put("resultDigest", crypto.mac("otp-result", nativeResult));
    var result = JSON.createObjectNode(); result.put("status", status); result.set("result", nativeResult);
    result.put("receipt", crypto.receipt("otp-bootstrap-complete/v1", facts));
    var saved = new AccountMaintenanceOperation(); saved.id = id; saved.realmId = owner.realm().getId();
    saved.operationId = request.operationId(); saved.accountId = account; saved.command = "otp.bootstrap-email-finish";
    saved.ownerClient = machine.clientId(); saved.ownerSubject = machine.subject(); saved.intentDigest = digest;
    saved.expectedState = request.expectedState(); saved.resultJson = canonical(result); owner.em().persist(saved);
    owner.em().flush();
    String current = crypto.mac("pending-profile", AccountLifecycleResource.lockedSnapshot(owner.em(), account));
    if (status == 201) {
      owner.bootstrap().state = "COMPLETE";
      owner.attempt().profileFingerprint = current;
    } else owner.bootstrap().emailPendingFingerprint = current;
    owner.em().flush();
    return Response.status(status).entity(result).header("Cache-Control", "no-store").build();
  }

  private static JsonNode emailResult(LifecycleAuthorization crypto, EmailOwner owner,
      String operationId, String digest, long expiry, JsonNode binding, JsonNode nativeResult,
      int status, String state) {
    fields(nativeResult, "info"); text(nativeResult, "info", 512, false);
    var facts = owner.receipt().deepCopy();
    var outcome = (com.fasterxml.jackson.databind.node.ObjectNode) facts;
    outcome.put("state", state); outcome.put("operationId", operationId);
    outcome.put("intentDigest", digest); outcome.put("status", status);
    outcome.put("resultDigest", crypto.mac("otp-result", nativeResult));
    outcome.put("deliveryValidUntil", expiry); outcome.set("emailCredential", binding);
    var result = JSON.createObjectNode(); result.put("status", status); result.put("deliveryState", state);
    result.set("result", nativeResult); result.put("receipt", crypto.receipt("otp-bootstrap-email-start/v1", outcome));
    return result;
  }

  private static void enlistEmail(KeycloakSession owner, LifecycleAuthorization crypto,
      String username, byte[] raw, String proof, String receipt,
      Function<ScopedOtpAccess.VerifiedOtpTarget, Response> send) {
    var factory = owner.getKeycloakSessionFactory(); var realmId = owner.getContext().getRealm().getId();
    var actualRequest = owner.getContext().getHttpRequest(); var connection = owner.getContext().getConnection();
    byte[] frozen = raw.clone();
    owner.getTransactionManager().enlistAfterCompletion(new org.keycloak.models.AbstractKeycloakTransaction() {
      protected void rollbackImpl() {}
      protected void commitImpl() {
        var claimed = new java.util.concurrent.atomic.AtomicBoolean(false);
        try {
          org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction(factory, fresh -> {
            fresh.getContext().setRealm(fresh.realms().getRealm(realmId));
            fresh.getContext().setHttpRequest(actualRequest); fresh.getContext().setConnection(connection);
            emailStart(fresh, crypto, username, frozen, proof, null, receipt, null, send, EmailPhase.CLAIM);
            fresh.getTransactionManager().enlistAfterCompletion(new org.keycloak.models.AbstractKeycloakTransaction() {
              protected void rollbackImpl() { claimed.set(false); }
              protected void commitImpl() { claimed.set(true); }
            });
          });
          if (!claimed.get()) return;
          org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction(factory, fresh -> {
            fresh.getContext().setRealm(fresh.realms().getRealm(realmId));
            fresh.getContext().setHttpRequest(actualRequest); fresh.getContext().setConnection(connection);
            emailStart(fresh, crypto, username, frozen, proof, null, receipt, null, send, EmailPhase.SEND);
          });
        } catch (RuntimeException refusedOrUnknown) {
          // The committed READY/SENDING owner survives. No credentials or provider detail is logged.
        }
      }
    });
  }

  private record EmailOwner(jakarta.persistence.EntityManager em, org.keycloak.models.RealmModel realm,
      ProtectedInvitationConfiguration config, ProtectedInvitationApproval approval,
      AccountLifecycleAttempt attempt, ProtectedOtpBootstrapState bootstrap, JsonNode receipt) {}

  private static EmailOwner emailOwner(KeycloakSession session, LifecycleAuthorization crypto,
      LifecycleAuthorization.CheckedMachine authenticated, ScopedOtpRequest request, String prepareReceipt) {
    if (prepareReceipt == null || prepareReceipt.length() > 8192) deny();
    var parts = prepareReceipt.split("\\.", -1);
    if (parts.length != 2 || !parts[0].matches("[A-Za-z0-9_-]+") || !parts[1].matches("[0-9a-f]{64}")) deny();
    JsonNode receipt;
    try { receipt = parse(java.util.Base64.getUrlDecoder().decode(parts[0])); }
    catch (IllegalArgumentException invalid) { deny(); return null; }
    fields(receipt, "v", "realmId", "approvalId", "attemptId", "accountId", "claimId", "executionId",
        "bootstrapIncarnation", "ownerClient", "ownerSubject", "originDigest", "authorityValidUntil", "state");
    if (number(receipt, "v", true) != 1 || !"PREPARED".equals(receipt.path("state").asText())
        || !LifecycleAuthorization.equal(prepareReceipt, crypto.receipt("otp-bootstrap-prepare/v1", receipt))
        || !LifecycleAuthorization.equal(request.expectedState(), crypto.mac("otp-bootstrap-state/v1", JSON.valueToTree(prepareReceipt)))) deny();
    var realm = session.getContext().getRealm();
    var config = ProtectedInvitationFactory.checkedBootstrapConfiguration(session);
    if (!realm.getId().equals(receipt.path("realmId").asText()) || !request.accountId().equals(receipt.path("accountId").asText())) deny();
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var realmRow = em.find(RealmEntity.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
    if (realmRow == null) deny(); em.refresh(realmRow);
    var approval = em.find(ProtectedInvitationApproval.class,
        ProtectedInvitationResource.key(realm.getId(), uuid(text(receipt, "approvalId", 36, false))), LockModeType.PESSIMISTIC_WRITE);
    if (approval == null) deny(); em.refresh(approval);
    var attempt = em.find(AccountLifecycleAttempt.class, ProtectedInvitationResource.protectedAttemptKey(
        realm.getId(), approval.approvalId, uuid(text(receipt, "attemptId", 36, false))), LockModeType.PESSIMISTIC_WRITE);
    if (attempt == null) deny(); em.refresh(attempt);
    var machine = new ProtectedInvitationAuthorization(config, crypto).requireMachine(session, Set.of("ACCOUNT_ADMIN"));
    String id = "bootstrap:" + crypto.mac("otp-bootstrap-row/v1", JSON.valueToTree(attempt.id));
    var bootstrap = em.find(ProtectedOtpBootstrapState.class, id, LockModeType.PESSIMISTIC_WRITE);
    if (bootstrap == null) deny(); em.refresh(bootstrap);
    if (!authenticated.clientId().equals(machine.clientId()) || !authenticated.subject().equals(machine.subject())
        || !LifecycleAuthorization.equal(prepareReceipt, bootstrap.prepareReceipt)
        || !realm.getId().equals(bootstrap.realmId) || !approval.approvalId.equals(bootstrap.approvalId)
        || !attempt.attemptId.equals(bootstrap.attemptId) || !request.accountId().equals(bootstrap.accountId)
        || !machine.clientId().equals(bootstrap.ownerClient) || !machine.subject().equals(bootstrap.ownerSubject)
        || !"BOUND".equals(approval.state) || !attempt.attemptId.equals(approval.boundAttemptId)
        || !"OPEN".equals(attempt.state) || attempt.generation != 0 || attempt.terminalOperation != null
        || !request.accountId().equals(attempt.accountId) || !bootstrap.executionId.equals(attempt.executionId)
        || !bootstrap.executionId.equals(attempt.createExecution)
        || !"backend-account-create".equals(attempt.ownerClient)
        || !config.actors.get("ACCOUNT_CREATE").equals(attempt.ownerSubject)) conflict();
    var scope = parse(attempt.scope);
    if (!"INVITATION".equals(request.target().path("origin").path("kind").asText())
        || !approval.workflowId.equals(request.target().path("origin").path("workflowId").asText())
        || !scope.path("tenantId").asText().equals(request.target().path("tenantId").asText())
        || !bootstrap.claimId.equals(scope.path("approvalBinding").path("acceptanceClaim").path("claimId").asText())
        || !approval.approvalId.equals(scope.path("approvalBinding").path("approvalId").asText())
        || !LifecycleAuthorization.equal(approval.scopeDigest, scope.path("approvalBinding").path("scopeDigest").asText())
        || approval.authorizationRevision != scope.path("approvalBinding").path("authorizationRevision").asLong(-1)) deny();
    return new EmailOwner(em, realm, config, approval, attempt, bootstrap, receipt);
  }

  private static UserModel currentEmailUser(KeycloakSession session, LifecycleAuthorization crypto,
      EmailOwner owner, String username, boolean emailPrepared) {
    if (!Instant.parse(owner.approval().validUntil).isAfter(Instant.now())) deny();
    var frozen = parse(owner.approval().scope).path("profile");
    var profile = owner.config().profiles.get(text(frozen, "id", 255, false));
    if (profile == null || !canonical(frozen).equals(canonical(profile.snapshot()))
        || !owner.attempt().groupId.equals(profile.groupId())
        || !owner.attempt().roleFingerprint.equals(crypto.mac("protected-initial-profile/v1", frozen))) deny();
    owner.config().validateProfile(session, profile);
    if (owner.realm().getComponentsStream(owner.realm().getId(), "org.keycloak.storage.UserStorageProvider").findAny().isPresent()) deny();
    var snapshot = AccountLifecycleResource.lockedSnapshot(owner.em(), owner.attempt().accountId);
    String expected = emailPrepared ? owner.bootstrap().emailPendingFingerprint : owner.attempt().profileFingerprint;
    if (expected == null || !owner.realm().getId().equals(snapshot.path("realmId").asText())
        || !username.equals(snapshot.path("username").asText()) || snapshot.path("enabled").asBoolean()
        || !LifecycleAuthorization.equal(expected, crypto.mac("pending-profile", snapshot))) conflict();
    var user = session.users().getUserById(owner.realm(), owner.attempt().accountId);
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) { cache.evict(owner.realm(), user); user = session.users().getUserById(owner.realm(), owner.attempt().accountId); }
    if (user == null || user.isEnabled()) conflict();
    return user;
  }

  private static void conflict() { throw new ClientErrorException("Pending OTP workflow conflicts", 409); }
}
