package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import java.util.Set;
import java.util.TreeSet;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.RealmEntity;

/** Separate finite operation grants over checked committed protected provenance; never approval authority. */
final class ProtectedAccountOperations {
  private static final String MARKER = "PROTECTED_ACCOUNT_OPERATIONS_V1";

  static boolean selected(JsonNode target) {
    return "SELF".equals(target.path("origin").path("kind").asText())
        && MARKER.equals(target.path("origin").path("humanAuthority").asText());
  }

  static JsonNode readSelfOtp(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String fullHumanHeader) {
    return readCurrent(session, crypto, request, fullHumanHeader, "otp.read");
  }

  static JsonNode readAccount(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String fullHumanHeader) {
    return readCurrent(session, crypto, request, fullHumanHeader, "account.read");
  }

  private static JsonNode readCurrent(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String fullHumanHeader, String operation) {
    if (!selected(request.target()) || !"read".equals(request.command())
        || !Set.of("otp.read", "account.read").contains(operation)) deny();
    if (fullHumanHeader == null || fullHumanHeader.length() > 32775
        || !fullHumanHeader.regionMatches(true, 0, "Bearer ", 0, 7))
      throw new jakarta.ws.rs.NotAuthorizedException("Bearer");
    String rawHuman = fullHumanHeader.substring(7);
    var config = ProtectedInvitationFactory.checkedBootstrapConfiguration(session);
    // This transient authentication supplies a locator only. Fresh operation authority is checked
    // after realm and provenance locks through the shared native current-human implementation.
    var authenticated = NativeHumanBearer.require(session, rawHuman);
    var realm = session.getContext().getRealm();
    if (!config.realmId.equals(realm.getId()) || !config.realmName.equals(realm.getName())
        || realm.getComponentsStream(realm.getId(), "org.keycloak.storage.UserStorageProvider").findAny().isPresent()) deny();
    var em = CurrentNativeHumanIdentity.entityManager(session);
    var lockedRealm = em.find(RealmEntity.class, config.realmId, LockModeType.PESSIMISTIC_WRITE);
    if (lockedRealm == null) deny();
    em.refresh(lockedRealm);
    // A non-locking exact-account projection is only a locator. It grants no authority; the
    // approval and attempt are then locked in protocol order and every immutable value checked.
    var locators = em.createQuery("select a.id, a.scope, a.attemptId from AccountLifecycleAttempt a"
        + " where a.realmId=:realm and a.accountId=:account", Object[].class)
        .setParameter("realm", config.realmId).setParameter("account", request.accountId())
        .setMaxResults(2).getResultList();
    if (locators.size() != 1) deny();
    var locator = locators.get(0);
    var scope = parse((String) locator[1]);
    if (!scope.path("approvalBinding").isObject()) deny();
    String approvalId = uuid(text(scope.path("approvalBinding"), "approvalId", 36, false));
    var approval = em.find(ProtectedInvitationApproval.class,
        ProtectedInvitationResource.key(config.realmId, approvalId), LockModeType.PESSIMISTIC_WRITE);
    if (approval == null) deny();
    em.refresh(approval);
    var attempt = em.find(AccountLifecycleAttempt.class, locator[0], LockModeType.PESSIMISTIC_WRITE);
    if (attempt == null) deny();
    em.refresh(attempt);
    if (!request.accountId().equals(attempt.accountId) || !locator[2].equals(attempt.attemptId)
        || !locator[1].equals(attempt.scope)) deny();
    var frozen = parse(approval.scope).path("profile");
    var profile = config.profiles.get(text(frozen, "id", 255, false));
    if (profile == null || !"TENANT_ADMIN".equals(profile.kind())
        || !canonical(profile.snapshot()).equals(canonical(frozen))) deny();
    var delegation = new ProtectedPeerDelegation(session, config, crypto);
    long tenant = delegation.committedTarget(approval, attempt, profile);
    if (!Long.toString(tenant).equals(request.target().path("tenantId").asText())) deny();
    var resolved = delegation.resolve(authenticated, em);
    var human = delegation.require(resolved, rawHuman);
    var origin = request.target().path("origin");
    if (!request.accountId().equals(human.subject()) || !human.subject().equals(origin.path("humanSubject").asText())
        || !human.issuer().equals(origin.path("humanIssuer").asText())
        || !human.clientId().equals(origin.path("humanClient").asText())) deny();
    var grants = config.bindingAccountOperations.get(human.subject());
    if (resolved.sourceProfile() != null) {
      var policies = config.peerPolicies.values().stream().filter(policy ->
          policy.sourceProfileId().equals(resolved.sourceProfile().id())
              && policy.sourceProfileVersion() == resolved.sourceProfile().version()).toList();
      if (policies.size() != 1) deny();
      grants = config.peerAccountOperations.get(policies.get(0).id());
    }
    if (grants == null || grants.stream().noneMatch(grant ->
        grant.authority().equals(resolved.binding().authority()) && grant.profiles().contains(profile.id())
            && grant.operations().contains(operation)
            && (!grant.selfOnly() || human.subject().equals(request.accountId()))
            && (grant.targetSubjects().isEmpty() || grant.targetSubjects().contains(request.accountId())))) deny();
    if ("TENANT_PEER".equals(resolved.binding().authority()) && human.tenantId() != tenant
        || "PLATFORM".equals(resolved.binding().authority()) && human.tenantId() != 0) deny();
    config.validateProfile(session, profile);
    var current = AccountLifecycleResource.lockedSnapshot(em, request.accountId());
    var groups = new TreeSet<String>(); current.path("groups").forEach(value -> groups.add(value.asText()));
    var tenantValues = current.path("attributes").path("tenantId");
    if (!config.realmId.equals(current.path("realmId").asText()) || !current.path("enabled").asBoolean()
        || !current.path("serviceAccountClientLink").isNull() || !current.path("federationLink").isNull()
        || !current.path("roles").isEmpty() || !groups.equals(Set.of(profile.groupId()))
        || tenantValues.size() != 1 || !Long.toString(tenant).equals(tenantValues.path(0).asText())) deny();
    for (var technical : config.installation.path("technicalSubjects"))
      if (request.accountId().equals(technical.asText())) deny();
    var state = JSON.createObjectNode();
    state.put("realmId", config.realmId); state.set("account", current);
    state.put("provenance", attempt.id); state.set("profile", profile.snapshot());
    var result = JSON.createObjectNode();
    for (String field : java.util.List.of("id", "username", "email", "firstName", "lastName", "enabled", "emailVerified"))
      result.set(field, current.path(field));
    result.put("tenantId", Long.toString(tenant));
    var locales = current.path("attributes").path("locale");
    if (!locales.isMissingNode() && locales.size() != 1) deny();
    result.set("preferredLanguage", locales.isMissingNode() ? JSON.nullNode() : locales.path(0));
    result.set("effectiveRoles", JSON.valueToTree(new TreeSet<>(profile.realmRoles())));
    boolean passwordChange = false;
    for (var action : current.path("requiredActions"))
      if (org.keycloak.models.UserModel.RequiredAction.UPDATE_PASSWORD.name().equals(action.asText())) passwordChange = true;
    result.put("passwordChangeRequired", passwordChange);
    result.put("state", crypto.mac("maintenance-state", state));
    return result;
  }

  private ProtectedAccountOperations() {}
}
