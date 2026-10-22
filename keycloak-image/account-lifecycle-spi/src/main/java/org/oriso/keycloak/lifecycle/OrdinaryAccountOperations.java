package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import java.util.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserCredentialModel;

/** Finite administration of one positively committed ordinary native profile. */
final class OrdinaryAccountOperations {
  private record Prepared(JsonNode response, JsonNode nativeState, GeneralPolicy.Profile profile,
      GeneralPolicy.Profile desired, MaintenanceLineage.Current lineage) {}

  static JsonNode read(KeycloakSession session, LifecycleAuthorization crypto, Map<String, Set<String>> mappings,
      GeneralPolicy policy, MaintenanceRequest request, String human) {
    return prepare(session, crypto, mappings, policy, request, human).response;
  }

  static JsonNode readCausal(KeycloakSession session, LifecycleAuthorization crypto, Map<String, Set<String>> mappings,
      GeneralPolicy policy, CausalPasswordRequest causal) {
    causal.requireLive();
    return prepare(session, crypto, mappings, policy, causal.target(), null, causal).response;
  }

  static void mutate(KeycloakSession session, LifecycleAuthorization crypto, Map<String, Set<String>> mappings,
      GeneralPolicy policy, MaintenanceRequest request, JsonNode body, String human) {
    var prepared = prepare(session, crypto, mappings, policy, request, human);
    if (!LifecycleAuthorization.equal(request.expectedState(), prepared.response.path("state").asText()))
      throw MaintenancePreflightRefusal.current(409);
    if ("reactivate".equals(request.command())
        && (!request.change().path("expectedUsername").equals(prepared.response.path("username"))
            || !request.change().path("expectedEmail").equals(prepared.response.path("email"))))
      throw MaintenancePreflightRefusal.current(409);
    var realm = session.getContext().getRealm();
    var user = session.users().getUserById(realm, request.accountId());
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) { cache.evict(realm, user); user = session.users().getUserById(realm, request.accountId()); }
    if (user == null) throw MaintenancePreflightRefusal.current(409);
    if ("reactivate".equals(request.command())
        && session.getProvider(org.keycloak.policy.PasswordPolicyManagerProvider.class)
            .validate(realm, user, request.change().path("password").textValue()) != null)
      throw MaintenancePreflightRefusal.passwordPolicy(request);
    // Every definite preflight check above precedes the first native write below.
    switch (request.command()) {
      case "profile", "email" -> profile(user, request.change());
      case "ordinary-profile" -> {
        var desired = session.groups().getGroupById(realm, prepared.desired.groupId);
        var current = session.groups().getGroupById(realm, prepared.profile.groupId);
        if (desired == null || current == null) throw new IllegalStateException("Profile changed during effect");
        if (!prepared.desired.groupId.equals(prepared.profile.groupId)) { user.leaveGroup(current); user.joinGroup(desired); }
        if (request.change().has("profile")) profile(user, request.change().path("profile"));
        MaintenanceLineage.append(session, crypto, request, body, prepared.lineage,
            prepared.desired.id, prepared.desired.version, request.target().path("tenantId"));
      }
      case "deactivate" -> user.setEnabled(false);
      case "reactivate" -> {
        user.setEnabled(false);
        if (!user.credentialManager().updateCredential(UserCredentialModel.password(request.change().path("password").textValue())))
          throw new IllegalStateException("Password effect did not complete");
        user.removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        session.users().setNotBeforeForUser(realm, user, org.keycloak.common.util.Time.currentTime());
        var nativeSessions = session.sessions().getUserSessionsStream(realm, user).toList();
        for (var nativeSession : nativeSessions)
          org.keycloak.services.managers.AuthenticationManager.backchannelLogout(session, realm, nativeSession,
              session.getContext().getUri(), session.getContext().getConnection(), session.getContext().getRequestHeaders(), true);
        if (session.sessions().getUserSessionsStream(realm, user).findAny().isPresent())
          throw new IllegalStateException("Session revocation did not complete");
        user.setEnabled(true);
      }
      default -> deny();
    }
    var em = CurrentNativeHumanIdentity.entityManager(session); em.flush();
    var fresh = AccountLifecycleResource.lockedSnapshot(em, request.accountId());
    if ("ordinary-profile".equals(request.command())
        && (fresh.path("groups").size() != 1 || !prepared.desired.groupId.equals(fresh.path("groups").path(0).asText())
            || !fresh.path("roles").isEmpty())) throw new IllegalStateException("Profile membership effect did not complete");
    if (Set.of("deactivate", "reactivate").contains(request.command())
        && fresh.path("enabled").asBoolean() != "reactivate".equals(request.command()))
      throw new IllegalStateException("Status effect did not complete");
    var changed = "ordinary-profile".equals(request.command()) ? request.change().path("profile") : request.change();
    if (Set.of("profile", "email", "ordinary-profile").contains(request.command()) && changed.isObject())
      for (var fields = changed.fields(); fields.hasNext();) {
        var field = fields.next();
        if (!field.getValue().equals(fresh.path(field.getKey()))) throw new IllegalStateException("Profile effect did not complete");
      }
  }

  private static Prepared prepare(KeycloakSession session, LifecycleAuthorization crypto,
      Map<String, Set<String>> mappings, GeneralPolicy policy, MaintenanceRequest request, String human) {
    return prepare(session, crypto, mappings, policy, request, human, null);
  }

  private static Prepared prepare(KeycloakSession session, LifecycleAuthorization crypto,
      Map<String, Set<String>> mappings, GeneralPolicy policy, MaintenanceRequest request, String human,
      CausalPasswordRequest causal) {
    if (policy == null || !Set.of("read", "profile", "email", "ordinary-profile", "deactivate", "reactivate")
        .contains(request.command())) deny();
    var realm = session.getContext().getRealm(); var em = CurrentNativeHumanIdentity.entityManager(session);
    var lockedRealm = em.find(org.keycloak.models.jpa.entities.RealmEntity.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
    if (lockedRealm == null) deny(); em.refresh(lockedRealm);
    if (realm.getComponentsStream(realm.getId(), "org.keycloak.storage.UserStorageProvider").findAny().isPresent()) deny();
    if (!em.createNativeQuery("select ID from ORISO_ACCOUNT_MAINTENANCE_OP where REALM_ID=:realm"
        + " and ACCOUNT_ID=:account and COMMAND='delete' for update")
        .setParameter("realm", realm.getId()).setParameter("account", request.accountId()).getResultList().isEmpty()) deny();
    var rows = em.createQuery("select a from AccountLifecycleAttempt a where a.realmId=:realm and a.accountId=:account",
        AccountLifecycleAttempt.class).setParameter("realm", realm.getId()).setParameter("account", request.accountId())
        .setLockMode(LockModeType.PESSIMISTIC_WRITE).setMaxResults(2).getResultList();
    if (rows.size() != 1) deny(); var row = rows.get(0); em.refresh(row);
    if (!"COMMITTED".equals(row.state) || !"commit".equals(row.terminalOperation)
        || !"backend-account-create".equals(row.ownerClient) || !crypto.creatorSubject.equals(row.ownerSubject)
        || row.creationProof == null || row.terminalReceipt == null || row.terminalDigest == null) deny();
    var scope = parse(row.scope); LifecycleGroups.scope(scope);
    var originalRoles = mappings.get(scope.path("initialGroup").asText());
    if (originalRoles == null || !LifecycleAuthorization.equal(row.roleFingerprint,
        crypto.mac("initial-roles", JSON.valueToTree(new TreeSet<>(originalRoles))))) deny();
    var baseline = policy.profileForGroup(row.groupId, originalRoles);
    verifyCommitted(crypto, realm.getName(), row, scope);
    var origin = JSON.createObjectNode(); origin.put("attempt", row.id); origin.put("creationProof", row.creationProof);
    origin.put("terminalReceipt", row.terminalReceipt); origin.set("scope", scope);
    var lineage = MaintenanceLineage.resolve(session, crypto, request.accountId(), crypto.mac("maintenance-provenance/v1", origin),
        "ORDINARY", baseline.id, baseline.version, scope.path("tenantId"));
    var profile = policy.profile(lineage.profileId(), lineage.profileVersion());
    var desired = "ordinary-profile".equals(request.command())
        ? policy.desiredProfile(request.change().path("group").asText()) : profile;
    if (!Objects.equals(LifecycleGroups.allowedKind(profile.realmRoles), LifecycleGroups.allowedKind(desired.realmRoles))) deny();
    if (causal != null) causal.requireProfile("ORDINARY", profile.id, profile.version);
    else {
      var source = HumanAdminSource.require(session, crypto, request, human);
      policy.requireAdmin(source, request, "account." + request.command(), profile, desired);
      if ("ordinary-profile".equals(request.command()) && request.change().has("profile"))
        policy.requireAdmin(source, request, "account.profile", profile, desired);
    }
    // All failures below are definite target/CAS preflight refusals for the actual authorized source.
    try {
      if (!lineage.tenant().equals(request.target().path("tenantId"))
          || policy.nativePolicy.subjects.contains(request.accountId())) deny();
      policy.validateProfile(session, profile); policy.validateProfile(session, desired);
      var current = AccountLifecycleResource.lockedSnapshot(em, request.accountId());
      if (!realm.getId().equals(current.path("realmId").asText()) || !current.path("serviceAccountClientLink").isNull()
          || !current.path("federationLink").isNull() || !current.path("roles").isEmpty()
          || current.path("groups").size() != 1 || !profile.groupId.equals(current.path("groups").path(0).asText())) deny();
      var tenants = current.path("attributes").path("tenantId");
      JsonNode actualTenant = tenants.isMissingNode() || tenants.isEmpty() ? JSON.nullNode() : tenants.path(0);
      if (!tenants.isMissingNode() && tenants.size() != 1 || !actualTenant.equals(lineage.tenant())
          || actualTenant.isNull() && !profile.allowUnassignedTenant) deny();
      if (causal != null) causal.requireNativeBinding(crypto, current);
      var state = JSON.createObjectNode(); state.set("account", current); state.put("realmId", realm.getId());
      state.put("provenance", row.id); state.put("groupId", profile.groupId);
      state.set("effectiveRoles", JSON.valueToTree(new TreeSet<>(profile.realmRoles)));
      if (lineage.digest() != null) state.put("lineageDigest", lineage.digest());
      var result = JSON.createObjectNode();
      for (String field : List.of("id", "username", "email", "firstName", "lastName", "enabled", "emailVerified"))
        result.set(field, current.path(field));
      result.set("tenantId", actualTenant);
      var locale = current.path("attributes").path("locale");
      if (!locale.isMissingNode() && locale.size() != 1) deny();
      result.set("preferredLanguage", locale.isMissingNode() ? JSON.nullNode() : locale.path(0));
      result.set("effectiveRoles", JSON.valueToTree(new TreeSet<>(profile.realmRoles)));
      boolean changeRequired = false;
      for (var action : current.path("requiredActions")) if ("UPDATE_PASSWORD".equals(action.asText())) changeRequired = true;
      result.put("passwordChangeRequired", changeRequired); result.put("state", crypto.mac("maintenance-state", state));
      if ("TWO_FACTOR_STATUS_V1".equals(request.include())) result.set("twoFactor", NativeOtpStatus.read(current));
      return new Prepared(result, current, profile, desired, lineage);
    } catch (jakarta.ws.rs.WebApplicationException refused) {
      int status = refused.getResponse().getStatus();
      if (causal == null && (status == 403 || status == 409)) throw MaintenancePreflightRefusal.current(status);
      throw refused;
    }
  }

  private static void verifyCommitted(LifecycleAuthorization crypto, String realmName,
      AccountLifecycleAttempt row, JsonNode scope) {
    var creation = JSON.createObjectNode(); creation.put("v", 1); creation.put("realmName", realmName);
    creation.put("realmId", row.realmId); creation.put("attemptId", row.attemptId); creation.put("accountId", row.accountId);
    creation.put("ownerClient", row.ownerClient); creation.put("ownerSubject", row.ownerSubject); creation.set("scope", scope);
    creation.put("initialGroupId", row.groupId); creation.put("initialRoleFingerprint", row.roleFingerprint);
    creation.put("creationFingerprint", row.creationFingerprint);
    var terminal = JSON.createObjectNode(); terminal.put("realmId", row.realmId); terminal.put("attemptId", row.attemptId);
    terminal.put("accountId", row.accountId); terminal.put("ownerClient", row.ownerClient); terminal.put("ownerSubject", row.ownerSubject);
    terminal.put("scope", row.scope); terminal.put("creationFingerprint", row.creationFingerprint); terminal.put("groupId", row.groupId);
    terminal.put("roleFingerprint", row.roleFingerprint); terminal.put("state", row.state); terminal.put("generation", row.generation);
    terminal.put("executionId", row.executionId); terminal.put("operation", row.terminalOperation); terminal.put("commandDigest", row.terminalDigest);
    if (!LifecycleAuthorization.equal(crypto.creationReceipt(creation), row.creationProof)
        || !LifecycleAuthorization.equal(crypto.receipt("terminal-receipt", terminal), row.terminalReceipt)) deny();
  }
  private static void profile(UserModel user, JsonNode change) {
    if (change.has("firstName")) { user.setFirstName(change.path("firstName").textValue()); user.setLastName(change.path("lastName").textValue()); }
    if (!Objects.equals(user.getEmail(), change.path("email").textValue())) {
      user.setEmail(change.path("email").textValue()); user.setEmailVerified(false);
    }
  }
  private OrdinaryAccountOperations() {}
}
