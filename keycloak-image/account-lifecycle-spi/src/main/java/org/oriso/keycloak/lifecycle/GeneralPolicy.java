package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;
import org.keycloak.models.KeycloakSession;

/** Positive ordinary profiles and finite self authority over one independently checked native human. */
final class GeneralPolicy {
  final CurrentNativeHumanIdentity.NativePolicy nativePolicy;
  private final List<Profile> profiles;
  private final List<AdminGrant> adminOperations;
  final WorkflowOperations workflowOperations;
  final Map<String,Adoption> adoptedAccounts;
  record Adoption(String accountId,String profileId,long profileVersion) {}

  private record AdminGrant(String authority, Set<String> profiles, Set<String> operations) {}

  GeneralPolicy(JsonNode config) {
    if (config == null || !config.isObject()) bad();
    var required = (com.fasterxml.jackson.databind.node.ObjectNode) config.deepCopy();
    required.remove("adminOperations"); required.remove("workflowOperations"); required.remove("adoptedAccounts");
    fields(required, "version", "native", "ordinaryProfiles");
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
    adminOperations = parseAdminOperations(config, ids);
    workflowOperations = new WorkflowOperations(config, ids);
    var adoptions=new TreeMap<String,Adoption>();
    if(config.has("adoptedAccounts")){
      var suppliedAdoptions=config.path("adoptedAccounts");if(!suppliedAdoptions.isArray()||suppliedAdoptions.size()>1000)bad();
      for(var value:suppliedAdoptions){
        fields(value,"accountId","ordinaryProfileId","profileVersion");
        String account=uuid(text(value,"accountId",36,false));String profileId=text(value,"ordinaryProfileId",100,false);
        long version=number(value,"profileVersion",true);
        if(profiles.stream().noneMatch(p->p.id.equals(profileId)&&p.version==version)
            ||adoptions.put(account,new Adoption(account,profileId,version))!=null)bad();
      }
    }
    adoptedAccounts=Map.copyOf(adoptions);
  }

  private static List<AdminGrant> parseAdminOperations(JsonNode config, Set<String> profileIds) {
    if (!config.has("adminOperations")) return List.of();
    var supplied = config.path("adminOperations");
    if (!supplied.isArray() || supplied.size() > 20) bad();
    var result = new ArrayList<AdminGrant>();
    var unique = new HashSet<AdminGrant>();
    var allowed = Set.of("account.read", "account.profile", "account.email",
        "account.ordinary-profile", "account.deactivate", "account.reactivate");
    for (var value : supplied) {
      fields(value, "authority", "targetProfiles", "operations", "selfOnly");
      String authority = text(value, "authority", 20, false);
      if (!Set.of("PLATFORM", "TENANT_PEER").contains(authority)
          || !value.path("selfOnly").isBoolean() || value.path("selfOnly").booleanValue()) bad();
      var targets = operationStrings(value.path("targetProfiles"), 20, 100);
      var operations = operationStrings(value.path("operations"), allowed.size(), 80);
      if (!profileIds.containsAll(targets) || !allowed.containsAll(operations)) bad();
      var grant = new AdminGrant(authority, targets, operations);
      if (!unique.add(grant)) bad();
      result.add(grant);
    }
    return List.copyOf(result);
  }

  private static Set<String> operationStrings(JsonNode value, int maximum, int length) {
    if (!value.isArray() || value.isEmpty() || value.size() > maximum) bad();
    var result = new HashSet<String>();
    for (var item : value) {
      if (!item.isTextual() || item.asText().isBlank() || item.asText().length() > length
          || item.asText().chars().anyMatch(c -> c < 32 || c == 127)
          || !result.add(item.asText())) bad();
    }
    return Set.copyOf(result);
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
    if (!Set.of("read", "locale", "profile", "password", "self-password").contains(request.command())) deny();
    return requireSelectedSelf(session, request, rawHumanBearer,
        "account." + ("self-password".equals(request.command()) ? "password" : request.command()));
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

  OrdinaryHuman requireSelfOtpEmailStart(KeycloakSession session, MaintenanceRequest request, String rawHumanBearer) {
    if (!"read".equals(request.command())) deny();
    return requireSelectedSelf(session, request, rawHumanBearer, "otp.email-start");
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

  void validateProfile(KeycloakSession session, Profile profile) {
    var current = NativeCurrentGrants.read(CurrentNativeHumanIdentity.entityManager(session), nativePolicy.realmId,
        Set.of(), Set.of(profile.groupId));
    if (!profile.realmRoles.equals(current.realmRoles()) || !profile.clientRoles.equals(current.clientRoles())
        || !current.groups().keySet().equals(Set.of(profile.groupId, profile.parentId))
        || !profile.path.equals(current.paths().get(profile.groupId))
        || !"/human-roles".equals(current.paths().get(profile.parentId))
        || !profile.parentId.equals(current.groups().get(profile.groupId).parentId())
        || current.groups().get(profile.parentId).parentId() != null) deny();
  }

  Profile profileForGroup(String groupId, Set<String> roles) {
    var found = profiles.stream().filter(p -> p.groupId.equals(groupId) && p.realmRoles.equals(roles)).toList();
    if (found.size() != 1) deny();
    return found.get(0);
  }

  Profile profile(String id, long version) {
    var found = profiles.stream().filter(p -> p.id.equals(id) && p.version == version).toList();
    if (found.size() != 1) deny();
    return found.get(0);
  }

  Profile desiredProfile(String path) {
    var found = profiles.stream().filter(p -> p.path.equals(path)).toList();
    if (found.size() != 1) deny();
    return found.get(0);
  }

  void requireAdmin(HumanAdminSource source, MaintenanceRequest request, String operation,
      Profile current, Profile desired) {
    source.targetTenant(request.target().path("tenantId"));
    for (var selected : new HashSet<>(List.of(current.id, desired.id)))
      if (adminOperations.stream().noneMatch(grant -> grant.authority.equals(source.authority())
          && grant.profiles.contains(selected) && grant.operations.contains(operation))) deny();
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

  static final class Profile {
    final String id, groupId, path, parentId;
    final long version;
    final Set<String> realmRoles, selfOperations;
    final Map<String, Set<String>> clientRoles;
    final boolean allowUnassignedTenant;
    final JsonNode snapshot;
    private Profile(JsonNode value) {
      snapshot=value.deepCopy();
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
      if (!operations.isArray() || operations.isEmpty() || operations.size() > 9) bad();
      var selected = new HashSet<String>();
      for (var operation : operations) {
        if (!operation.isTextual() || !Set.of("account.read", "account.locale", "account.profile", "account.password", "otp.read", "otp.app-setup", "otp.delete", "otp.email-start", "otp.email-finish").contains(operation.asText())
            || !selected.add(operation.asText())) bad();
      }
      selfOperations = Set.copyOf(selected);
    }
  }
}
