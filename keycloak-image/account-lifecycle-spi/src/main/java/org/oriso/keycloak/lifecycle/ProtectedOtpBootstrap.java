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
    if (deadline <= now) deny();
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

  private static void conflict() { throw new ClientErrorException("Pending OTP workflow conflicts", 409); }
}
