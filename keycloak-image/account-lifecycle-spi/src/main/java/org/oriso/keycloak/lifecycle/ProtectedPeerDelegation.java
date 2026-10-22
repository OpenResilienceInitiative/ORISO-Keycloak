package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AuthenticationManager;

/** Finite own-tenant authority rooted only in an actual consumed protected creation. */
final class ProtectedPeerDelegation {
  private final KeycloakSession session;
  private final ProtectedInvitationConfiguration config;
  private final LifecycleAuthorization crypto;

  record Resolved(ProtectedInvitationConfiguration.Binding binding,
      ProtectedInvitationConfiguration.Profile sourceProfile) {}

  ProtectedPeerDelegation(KeycloakSession session, ProtectedInvitationConfiguration config,
      LifecycleAuthorization crypto) {
    this.session = session; this.config = config; this.crypto = crypto;
  }

  Resolved resolve(AuthenticationManager.AuthResult authenticated, EntityManager em) {
    String subject = uuid(authenticated.getUser().getId());
    if (!subject.equals(authenticated.getToken().getSubject())) deny();
    var primary = config.bindings.get(subject);
    if (primary != null) return new Resolved(primary, null);
    // Current locking projection: an older RR read view cannot discover authority.
    var ids = em.createNativeQuery("select ID from ORISO_PROTECTED_INVITATION_APPROVAL"
            + " where REALM_ID = :realm and DELEGATED_SUBJECT = :subject for update")
        .setParameter("realm", config.realmId).setParameter("subject", subject).getResultList();
    if (ids.size() != 1) deny();
    var origin = em.find(ProtectedInvitationApproval.class, ids.get(0), LockModeType.PESSIMISTIC_WRITE);
    if (origin == null) deny();
    em.refresh(origin);
    if (!subject.equals(origin.delegatedSubject) || origin.delegationSnapshot == null
        || origin.boundAttemptId == null) deny();
    var attempt = em.find(AccountLifecycleAttempt.class,
        ProtectedInvitationResource.protectedAttemptKey(config.realmId, origin.approvalId, origin.boundAttemptId),
        LockModeType.PESSIMISTIC_WRITE);
    if (attempt == null) deny();
    em.refresh(attempt);
    var profile = sourceProfile(origin);
    var policy = policy(profile);
    if (policy == null) deny();
    long tenant = provenance(origin, attempt, profile);
    if (!subject.equals(attempt.accountId)
        || !origin.delegationSnapshot.equals(snapshot(origin, attempt, profile, policy, tenant))) deny();
    var value = JSON.createObjectNode();
    for (String name : List.of("realmId", "issuer", "technicalSubjects", "technicalGroupIds", "technicalRoles"))
      value.set(name, config.installation.path(name).deepCopy());
    value.put("subject", subject); value.put("version", policy.version());
    value.putArray("tenantIds").add(tenant);
    value.set("clientIds", policy.snapshot().path("humanClientIds").deepCopy());
    value.set("audienceSets", policy.snapshot().path("audienceSets").deepCopy());
    value.set("realmRoles", policy.snapshot().path("realmRoles").deepCopy());
    value.set("clientRoles", policy.snapshot().path("clientRoles").deepCopy());
    return new Resolved(new ProtectedInvitationConfiguration.Binding("TENANT_PEER", Set.of(tenant),
        policy.profiles(), CurrentHumanAuthorization.policy(value)), profile);
  }

  CurrentHumanAuthorization.VerifiedHuman require(Resolved resolved) {
    var human = CurrentHumanAuthorization.require(session, resolved.binding().policy());
    return checkedProfile(resolved, human);
  }

  CurrentHumanAuthorization.VerifiedHuman require(Resolved resolved, String rawHumanBearer) {
    return checkedProfile(resolved,
        CurrentHumanAuthorization.require(session, resolved.binding().policy(), rawHumanBearer));
  }

  private CurrentHumanAuthorization.VerifiedHuman checkedProfile(Resolved resolved,
      CurrentHumanAuthorization.VerifiedHuman human) {
    var profile = resolved.sourceProfile();
    if (profile != null) {
      config.validateProfile(session, profile);
      // Reuse the native current locked scalar projection, never a cached user getter.
      var user = AccountLifecycleResource.lockedSnapshot(CurrentNativeHumanIdentity.entityManager(session), human.subject());
      var groups = new TreeSet<String>();
      user.path("groups").forEach(group -> groups.add(group.asText()));
      if (!groups.equals(Set.of(profile.groupId()))) deny();
    }
    return human;
  }

  // Facts only. The original peer provenance verifier and its TENANT_ADMIN semantics are unchanged.
  long committedTarget(ProtectedInvitationApproval origin, AccountLifecycleAttempt attempt,
      ProtectedInvitationConfiguration.Profile profile) {
    return provenance(origin, attempt, profile);
  }

  void recordConsumed(ProtectedInvitationApproval origin, AccountLifecycleAttempt attempt) {
    if (origin.delegatedSubject != null || origin.delegationSnapshot != null)
      throw new jakarta.ws.rs.ClientErrorException(409);
    var stored = parse(origin.scope).path("profile");
    if (!"TENANT_ADMIN".equals(stored.path("kind").asText())) return;
    var policy = policy(text(stored, "id", 255, false), number(stored, "version", true));
    if (policy == null) return; // Optional withdrawal cannot add a new first-COMMIT check.
    var profile = sourceProfile(origin);
    long tenant = provenance(origin, attempt, profile);
    String immutable = snapshot(origin, attempt, profile, policy, tenant);
    if (immutable.getBytes(StandardCharsets.UTF_8).length > 16000) bad();
    origin.delegatedSubject = uuid(attempt.accountId);
    origin.delegationSnapshot = immutable;
    // Caller flushes these with native enable/group, COMMITTED and CONSUMED.
  }

  private ProtectedInvitationConfiguration.Profile sourceProfile(ProtectedInvitationApproval origin) {
    var frozen = parse(origin.scope).path("profile");
    var profile = config.profiles.get(text(frozen, "id", 255, false));
    if (profile == null || !"TENANT_ADMIN".equals(profile.kind())
        || !canonical(profile.snapshot()).equals(canonical(frozen))) deny();
    return profile;
  }

  private ProtectedInvitationConfiguration.PeerPolicy policy(ProtectedInvitationConfiguration.Profile profile) {
    return policy(profile.id(), profile.version());
  }

  private ProtectedInvitationConfiguration.PeerPolicy policy(String profileId, long profileVersion) {
    var policies = config.peerPolicies.values().stream().filter(candidate ->
        profileId.equals(candidate.sourceProfileId()) && profileVersion == candidate.sourceProfileVersion()).toList();
    if (policies.size() > 1) deny();
    return policies.isEmpty() ? null : policies.get(0);
  }

  private long provenance(ProtectedInvitationApproval origin, AccountLifecycleAttempt attempt,
      ProtectedInvitationConfiguration.Profile profile) {
    if (!config.realmId.equals(origin.realmId) || !"CONSUMED".equals(origin.state)
        || origin.approvalReceipt == null || origin.transitionReceipt == null || origin.boundAttemptId == null
        || !config.realmId.equals(attempt.realmId) || !"COMMITTED".equals(attempt.state)
        || !"commit".equals(attempt.terminalOperation) || attempt.terminalDigest == null
        || attempt.terminalReceipt == null || attempt.creationProof == null || attempt.accountId == null
        || !origin.boundAttemptId.equals(attempt.attemptId) || attempt.generation != 0
        || attempt.createExecution == null || !attempt.createExecution.equals(attempt.executionId)
        || !ProtectedInvitationResource.protectedAttemptKey(config.realmId, origin.approvalId, origin.boundAttemptId).equals(attempt.id)
        || !profile.groupId().equals(attempt.groupId)
        || !LifecycleAuthorization.equal(crypto.mac("protected-initial-profile/v1", profile.snapshot()), attempt.roleFingerprint)) deny();
    var enriched = parse(origin.scope);
    var request = parse(origin.request);
    fields(request, "scope");
    var scope = request.path("scope");
    if (!canonical(scope).equals(canonical(enriched.path("scope")))
        || !config.realmId.equals(enriched.path("realmId").asText())
        || !origin.issuerSubject.equals(enriched.path("issuerSubject").asText())
        || !config.issuer.equals(enriched.path("issuer").asText())
        || !LifecycleAuthorization.equal(crypto.mac("protected-approval-scope/v1", enriched), origin.scopeDigest)
        || !"TENANT_ADMIN".equals(scope.path("protectedKind").asText())
        || !profile.id().equals(scope.path("protectedProfileId").asText())
        || !origin.workflowId.equals(scope.path("workflowId").asText())
        || !origin.inviteId.equals(scope.path("inviteId").asText())
        || origin.authorizationRevision != number(scope, "authorizationRevision", true)
        || !origin.validUntil.equals(scope.path("validUntil").asText())
        || !scope.path("creatorClient").asText().equals(attempt.ownerClient)
        || !scope.path("creatorSubject").asText().equals(attempt.ownerSubject)) deny();
    var tenants = HumanPolicyJson.tenants(scope.path("targetTenantIds"));
    if (tenants.size() != 1 || tenants.iterator().next() <= 0) deny();
    long tenant = tenants.iterator().next();
    var requestBinding = JSON.createObjectNode(); requestBinding.set("request", request);
    requestBinding.put("issuerRealm", origin.realmId); requestBinding.put("issuerSubject", origin.issuerSubject);
    if (!LifecycleAuthorization.equal(crypto.mac("protected-approval-request/v1", requestBinding), origin.requestDigest)) deny();
    var receipt = parse(origin.approvalReceipt);
    fields(receipt, "approvalId", "scopeDigest", "issuerSubject", "bindingVersion", "profileVersion",
        "validUntil", "approvalRequestDigest", "receipt");
    var issued = receipt.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) issued).remove("receipt");
    if (!LifecycleAuthorization.equal(crypto.receipt("protected-approval-receipt/v1", issued), receipt.path("receipt").asText())
        || !origin.approvalId.equals(receipt.path("approvalId").asText())
        || !origin.scopeDigest.equals(receipt.path("scopeDigest").asText())
        || !origin.issuerSubject.equals(receipt.path("issuerSubject").asText())
        || !origin.requestDigest.equals(receipt.path("approvalRequestDigest").asText())
        || !origin.validUntil.equals(receipt.path("validUntil").asText())
        || profile.version() != number(receipt, "profileVersion", true)
        || number(receipt, "bindingVersion", true) <= 0) deny();
    var internal = parse(attempt.scope);
    var acceptance = internal.path("approvalBinding").path("acceptanceClaim");
    fields(acceptance, "workflowId", "inviteId", "authorizationRevision", "claimId", "journalVersion");
    uuid(text(acceptance, "claimId", 36, false)); number(acceptance, "journalVersion", true);
    if (!origin.workflowId.equals(acceptance.path("workflowId").asText())
        || !origin.inviteId.equals(acceptance.path("inviteId").asText())
        || origin.authorizationRevision != number(acceptance, "authorizationRevision", true)
        || !attempt.scope.equals(canonical(ProtectedInvitationResource.internalScope(origin, scope, enriched, acceptance)))) deny();
    var creation = JSON.createObjectNode(); creation.put("v", 1); creation.put("realmName", config.realmName);
    creation.put("realmId", attempt.realmId); creation.put("attemptId", attempt.attemptId);
    creation.put("accountId", attempt.accountId); creation.put("ownerClient", attempt.ownerClient);
    creation.put("ownerSubject", attempt.ownerSubject); creation.set("scope", internal);
    creation.put("initialGroupId", attempt.groupId); creation.put("initialRoleFingerprint", attempt.roleFingerprint);
    creation.put("creationFingerprint", attempt.creationFingerprint);
    if (!LifecycleAuthorization.equal(crypto.creationReceipt(creation), attempt.creationProof)) deny();
    var terminal = JSON.createObjectNode(); terminal.put("realmId", attempt.realmId);
    terminal.put("attemptId", attempt.attemptId); terminal.put("accountId", attempt.accountId);
    terminal.put("ownerClient", attempt.ownerClient); terminal.put("ownerSubject", attempt.ownerSubject);
    terminal.put("scope", attempt.scope); terminal.put("creationFingerprint", attempt.creationFingerprint);
    terminal.put("groupId", attempt.groupId); terminal.put("roleFingerprint", attempt.roleFingerprint);
    terminal.put("state", attempt.state); terminal.put("generation", attempt.generation);
    terminal.put("executionId", attempt.executionId); terminal.put("operation", attempt.terminalOperation);
    terminal.put("commandDigest", attempt.terminalDigest);
    if (!LifecycleAuthorization.equal(crypto.receipt("terminal-receipt", terminal), attempt.terminalReceipt)) deny();
    var consumed = JSON.createObjectNode(); consumed.put("operation", "protected-invitation.consume");
    consumed.put("state", "CONSUMED"); consumed.put("approvalId", origin.approvalId);
    consumed.put("scopeDigest", origin.scopeDigest); consumed.put("boundAttemptId", origin.boundAttemptId);
    consumed.put("accountId", attempt.accountId); consumed.put("terminalReceipt", attempt.terminalReceipt);
    consumed.put("receipt", crypto.receipt("protected-approval-consume/v1", consumed.deepCopy()));
    if (!canonical(consumed).equals(origin.transitionReceipt)) deny();
    return tenant;
  }

  private String snapshot(ProtectedInvitationApproval origin, AccountLifecycleAttempt attempt,
      ProtectedInvitationConfiguration.Profile profile, ProtectedInvitationConfiguration.PeerPolicy policy, long tenant) {
    var value = JSON.createObjectNode(); value.put("v", 1); value.put("realmId", origin.realmId);
    value.put("delegatedSubject", attempt.accountId); value.put("tenantId", tenant);
    value.put("originApprovalId", origin.approvalId); value.put("authorizationRevision", origin.authorizationRevision);
    value.put("scopeDigest", origin.scopeDigest); value.put("boundAttemptId", attempt.attemptId);
    value.put("executionId", attempt.executionId); value.put("generation", attempt.generation);
    value.put("profileId", profile.id()); value.put("profileVersion", profile.version());
    value.set("delegationPolicy", policy.snapshot().deepCopy());
    return canonical(value);
  }
}
