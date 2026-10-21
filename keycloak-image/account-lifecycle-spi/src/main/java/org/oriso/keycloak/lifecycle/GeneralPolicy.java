package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;
import org.keycloak.models.KeycloakSession;

/** Positive ordinary profiles and finite self authority over one independently checked native human. */
final class GeneralPolicy {
  final CurrentNativeHumanIdentity.NativePolicy nativePolicy;
  private final List<Profile> profiles;

  GeneralPolicy(JsonNode config) {
    fields(config, "version", "native", "ordinaryProfiles");
    if (number(config, "version", true) != 1) bad();
    nativePolicy = CurrentNativeHumanIdentity.nativePolicy(config.path("native"));
    var supplied = config.path("ordinaryProfiles");
    if (!supplied.isArray() || supplied.isEmpty() || supplied.size() > 20) bad();
    var found = new ArrayList<Profile>();
    var ids = new HashSet<String>();
    var groups = new HashSet<String>();
    for (var item : supplied) {
      var profile = new Profile(item);
      if (!ids.add(profile.id) || !groups.add(profile.groupId)
          || nativePolicy.groups.contains(profile.groupId)
          || !Collections.disjoint(profile.realmRoles, nativePolicy.technicalRoles)) bad();
      found.add(profile);
    }
    profiles = List.copyOf(found);
  }

  void validateInstallation(KeycloakSession session) {
    CurrentNativeHumanIdentity.validateInstallation(session, nativePolicy);
    var em = CurrentNativeHumanIdentity.entityManager(session);
    for (var profile : profiles) {
      var current = NativeCurrentGrants.read(em, nativePolicy.realmId, Set.of(), Set.of(profile.groupId));
      if (!profile.realmRoles.equals(current.realmRoles()) || !profile.clientRoles.equals(current.clientRoles())
          || !current.groups().keySet().equals(Set.of(profile.groupId, profile.parentId))
          || !profile.path.equals(current.paths().get(profile.groupId))
          || !"/human-roles".equals(current.paths().get(profile.parentId))
          || !profile.parentId.equals(current.groups().get(profile.groupId).parentId())
          || current.groups().get(profile.parentId).parentId() != null) deny();
    }
  }

  OrdinaryHuman requireSelf(KeycloakSession session, MaintenanceRequest request, String rawHumanBearer) {
    if (!Set.of("read", "locale").contains(request.command())) deny();
    return requireSelectedSelf(session, request, rawHumanBearer, "account." + request.command());
  }

  OrdinaryHuman requireSelfOtpRead(KeycloakSession session, MaintenanceRequest request, String rawHumanBearer) {
    if (!"read".equals(request.command())) deny();
    return requireSelectedSelf(session, request, rawHumanBearer, "otp.read");
  }

  OrdinaryHuman requireSelfOtpAppSetup(KeycloakSession session, MaintenanceRequest request, String rawHumanBearer) {
    if (!"read".equals(request.command())) deny();
    return requireSelectedSelf(session, request, rawHumanBearer, "otp.app-setup");
  }

  OrdinaryHuman requireSelfOtpDelete(KeycloakSession session, MaintenanceRequest request, String rawHumanBearer) {
    if (!"read".equals(request.command())) deny();
    return requireSelectedSelf(session, request, rawHumanBearer, "otp.delete");
  }

  OrdinaryHuman requireSelfOtpEmailFinish(KeycloakSession session, MaintenanceRequest request, String rawHumanBearer) {
    if (!"read".equals(request.command())) deny();
    return requireSelectedSelf(session, request, rawHumanBearer, "otp.email-finish");
  }

  private OrdinaryHuman requireSelectedSelf(KeycloakSession session, MaintenanceRequest request,
      String rawHumanBearer, String selectedOperation) {
    var origin = request.target().path("origin");
    if (!"SELF".equals(origin.path("kind").asText()) || !origin.path("humanAuthority").isNull()) deny();
    // Caller has acquired the realm and target-provenance locks before these fresh human locks.
    if (rawHumanBearer == null || rawHumanBearer.length() > 32775
        || !rawHumanBearer.regionMatches(true, 0, "Bearer ", 0, 7))
      throw new jakarta.ws.rs.NotAuthorizedException("Bearer");
    var human = CurrentNativeHumanIdentity.require(session, nativePolicy, rawHumanBearer.substring(7));
    if (!request.accountId().equals(human.subject())
        || !human.subject().equals(origin.path("humanSubject").asText())
        || !human.issuer().equals(origin.path("humanIssuer").asText())
        || !human.clientId().equals(origin.path("humanClient").asText())
        || human.tenantId() != null && human.tenantId() <= 0) deny();
    JsonNode actualTenant = human.tenantId() == null ? JSON.nullNode() : JSON.valueToTree(human.tenantId().toString());
    if (!actualTenant.equals(request.target().path("tenantId"))) deny();
    Profile matched = null;
    for (var profile : profiles) {
      if (!human.directGroupIds().equals(Set.of(profile.groupId))) continue;
      var group = human.currentGroups().get(profile.groupId);
      var parent = human.currentGroups().get(profile.parentId);
      if (group == null || parent == null || !profile.path.equals(group.path())
          || !profile.parentId.equals(group.parentId()) || !"/human-roles".equals(parent.path())
          || parent.parentId() != null || !human.currentGroups().keySet().equals(Set.of(profile.groupId, profile.parentId))
          || !profile.realmRoles.equals(human.realmRoles()) || !profile.clientRoles.equals(human.clientRoles())
          || human.tenantId() == null && !profile.allowUnassignedTenant
          || !profile.selfOperations.contains(selectedOperation)) deny();
      if (matched != null) deny();
      matched = profile;
    }
    if (matched == null) deny();
    return new OrdinaryHuman(human, matched.id, matched.version);
  }

  /** Classification result carries no peer, protected, creation or arbitrary operation grant. */
  static final class OrdinaryHuman {
    private final CurrentNativeHumanIdentity.VerifiedHuman human;
    private final String profileId;
    private final long profileVersion;
    private OrdinaryHuman(CurrentNativeHumanIdentity.VerifiedHuman human, String profileId, long version) {
      this.human = human;
      this.profileId = profileId;
      this.profileVersion = version;
    }
    CurrentNativeHumanIdentity.VerifiedHuman identity() { return human; }
    String profileId() { return profileId; }
    long profileVersion() { return profileVersion; }
  }

  private static final class Profile {
    final String id, groupId, path, parentId;
    final long version;
    final Set<String> realmRoles, selfOperations;
    final Map<String, Set<String>> clientRoles;
    final boolean allowUnassignedTenant;
    private Profile(JsonNode value) {
      fields(value, "id", "version", "groupId", "groupPath", "groupParentId", "realmRoles", "clientRoles", "allowUnassignedTenant", "selfOperations");
      id = text(value, "id", 100, false);
      version = number(value, "version", true);
      groupId = text(value, "groupId", 255, false);
      path = text(value, "groupPath", 512, false);
      parentId = text(value, "groupParentId", 255, false);
      if (!path.matches("/human-roles/[a-z0-9-]{1,80}") || groupId.equals(parentId)) bad();
      realmRoles = HumanPolicyJson.strings(value.path("realmRoles"), 1, 10, 255);
      clientRoles = HumanPolicyJson.clientRoles(value.path("clientRoles"));
      if (!LifecycleGroups.KNOWN.containsAll(realmRoles) || LifecycleGroups.allowedKind(realmRoles) == null) bad();
      if (!value.path("allowUnassignedTenant").isBoolean()) bad();
      allowUnassignedTenant = value.path("allowUnassignedTenant").asBoolean();
      var operations = value.path("selfOperations");
      if (!operations.isArray() || operations.isEmpty() || operations.size() > 7) bad();
      var selected = new HashSet<String>();
      for (var operation : operations) {
        if (!operation.isTextual() || !Set.of("account.read", "account.locale", "otp.read", "otp.app-setup", "otp.delete", "otp.email-start", "otp.email-finish").contains(operation.asText())
            || !selected.add(operation.asText())) bad();
      }
      selfOperations = Set.copyOf(selected);
    }
  }
}
