package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;
import org.keycloak.models.KeycloakSession;

/** Independently reviewed installation data; never populated from a public request. */
final class ProtectedInvitationConfiguration {
  static final Set<String> ACTORS = Set.of("SETUP", "ACCOUNT_CREATE", "ACCOUNT_ADMIN", "MAIL", "RUNTIME");
  final String realmId, realmName, issuer;
  final JsonNode installation;
  final Map<String, String> actors;
  final Map<String, Binding> bindings;
  final Map<String, Profile> profiles;
  final Map<String, PeerPolicy> peerPolicies;
  final Map<String, List<OperationGrant>> bindingAccountOperations, peerAccountOperations;
  final Map<String, Adoption> adoptedAccounts;
  final WorkflowOperations workflowOperations;

  private static final Set<String> ACCOUNT_OPERATIONS = Set.of("account.read", "account.profile",
      "account.email", "account.locale", "account.reassign-tenant", "account.password", "account.deactivate", "account.reactivate",
      "otp.read", "otp.app-setup", "otp.delete", "otp.email-start", "otp.email-finish");

  record Binding(String authority, Set<Long> tenants, Set<String> profiles, CurrentHumanAuthorization.Policy policy) {}
  record Profile(String id, long version, String kind, Set<String> modes, String groupId, String groupPath,
      Set<String> realmRoles, Map<String, Set<String>> clientRoles, JsonNode snapshot) {}
  record PeerPolicy(String id, long version, String sourceProfileId, long sourceProfileVersion,
      Set<String> clients, Set<Set<String>> audiences, Set<String> profiles,
      Set<String> realmRoles, Map<String, Set<String>> clientRoles,
      CurrentNativeHumanIdentity.NativePolicy nativePolicy, JsonNode snapshot) {}
  record OperationGrant(String authority, Set<String> profiles, Set<String> operations,
      boolean selfOnly, Set<String> targetSubjects) {}
  record Adoption(String accountId, String profileId, long profileVersion) {}

  ProtectedInvitationConfiguration(JsonNode config) {
    // The optional installed rule is metadata, never a public human binding.
    var required = without(config, "peerDelegationPolicies", "adoptedAccounts", "workflowOperations");
    fields(required, "realmId", "realmName", "issuer", "technicalSubjects", "technicalGroupIds", "technicalRoles",
        "actorSubjects", "machineAudienceSets", "bindings", "profiles");
    installation = config.deepCopy();
    realmId = text(config, "realmId", 255, false);
    realmName = text(config, "realmName", 255, false);
    issuer = text(config, "issuer", 512, false);
    fields(config.path("actorSubjects"), ACTORS.toArray(String[]::new));
    fields(config.path("machineAudienceSets"), "SETUP", "ACCOUNT_CREATE", "ACCOUNT_ADMIN");
    actors = new TreeMap<>();
    for (String actor : ACTORS) actors.put(actor, uuid(text(config.path("actorSubjects"), actor, 36, false)));
    if (new HashSet<>(actors.values()).size() != 5) bad();
    var technical = HumanPolicyJson.strings(config.get("technicalSubjects"), 5, 1000, 36);
    if (!technical.containsAll(actors.values())) bad();
    for (var actor : Map.of("SETUP", Set.of("tenantservice", "agencyservice", "consultingtypeservice", "userservice"),
        "ACCOUNT_CREATE", Set.of("oriso-account-lifecycle", "userservice"),
        "ACCOUNT_ADMIN", Set.of("oriso-account-lifecycle", "oriso-otp", "userservice")).entrySet())
      if (!actor.getValue().equals(HumanPolicyJson.strings(config.path("machineAudienceSets").get(actor.getKey()), 1, 30, 255))) bad();
    var configuredBindings = config.get("bindings");
    if (configuredBindings == null || !configuredBindings.isArray() || configuredBindings.isEmpty() || configuredBindings.size() > 100) bad();
    var bySubject = new TreeMap<String, Binding>();
    for (var binding : configuredBindings) {
      fields(without(binding, "accountOperations"), "subject", "authority", "authorizerTenantIds", "humanClientIds", "audienceSets", "protectedProfileIds", "realmRoles", "clientRoles", "version");
      String authority = text(binding, "authority", 20, false);
      var tenants = HumanPolicyJson.tenants(binding.get("authorizerTenantIds"));
      var roles = HumanPolicyJson.strings(binding.get("realmRoles"), 1, 100, 255);
      if (!("PLATFORM".equals(authority) && tenants.equals(Set.of(0L)) && roles.containsAll(Set.of("agency-admin", "tenant-admin")))
          && !("TENANT_PEER".equals(authority) && !tenants.contains(0L) && (roles.contains("tenant-admin") || roles.contains("single-tenant-admin")))) bad();
      var policy = JSON.createObjectNode();
      for (String key : List.of("realmId", "issuer", "technicalSubjects", "technicalGroupIds", "technicalRoles")) policy.set(key, config.get(key));
      for (String key : List.of("subject", "audienceSets", "realmRoles", "clientRoles", "version")) policy.set(key, binding.get(key));
      policy.set("tenantIds", binding.get("authorizerTenantIds"));
      policy.set("clientIds", binding.get("humanClientIds"));
      String subject = uuid(text(binding, "subject", 36, false));
      if (bySubject.put(subject, new Binding(authority, tenants,
          HumanPolicyJson.strings(binding.get("protectedProfileIds"), 1, 100, 255), CurrentHumanAuthorization.policy(policy))) != null) bad();
    }
    bindings = Map.copyOf(bySubject);
    var configuredProfiles = config.get("profiles");
    if (configuredProfiles == null || !configuredProfiles.isArray() || configuredProfiles.isEmpty() || configuredProfiles.size() > 100) bad();
    var byProfile = new TreeMap<String, Profile>();
    for (var profile : configuredProfiles) {
      fields(profile, "id", "version", "kind", "tenantModes", "groupId", "groupPath", "realmRoles", "clientRoles",
          "usernamePolicy", "firstNamePolicy", "lastNamePolicy");
      String id = text(profile, "id", 255, false), kind = text(profile, "kind", 30, false);
      var modes = HumanPolicyJson.strings(profile.get("tenantModes"), 1, 2, 20);
      var roles = HumanPolicyJson.strings(profile.get("realmRoles"), 1, 100, 255);
      var clientRoles = HumanPolicyJson.clientRoles(profile.get("clientRoles"));
      if (!Set.of("EXISTING", "RESERVED_NEW").containsAll(modes)
          || !("PLATFORM_ADMIN".equals(kind) && modes.equals(Set.of("EXISTING")) && roles.containsAll(Set.of("agency-admin", "tenant-admin")))
              && !("TENANT_ADMIN".equals(kind) && (roles.contains("tenant-admin") || roles.contains("single-tenant-admin")))
          || !Collections.disjoint(roles, HumanPolicyJson.strings(config.get("technicalRoles"), 1, 200, 255))
          || clientRoles.containsKey("realm-management")
          || !"USERNAME_TRANSCODER_V1".equals(text(profile, "usernamePolicy", 80, false))
          || !"INVITE_WITH_EMAIL_LOCAL_PART_FALLBACK".equals(text(profile, "firstNamePolicy", 80, false))
          || !"INVITE_WITH_ADMIN_FALLBACK".equals(text(profile, "lastNamePolicy", 80, false))) bad();
      if (byProfile.put(id, new Profile(id, number(profile, "version", true), kind, modes,
          text(profile, "groupId", 255, false), text(profile, "groupPath", 512, false), roles, clientRoles, profile.deepCopy())) != null) bad();
    }
    profiles = Map.copyOf(byProfile);
    for (var binding : bindings.values()) if (!profiles.keySet().containsAll(binding.profiles())) bad();
    peerPolicies = peerPolicies(config);
    var primaryOperations = new TreeMap<String, List<OperationGrant>>();
    for (var binding : configuredBindings) {
      String subject = text(binding, "subject", 36, false);
      primaryOperations.put(subject, operations(binding, bindings.get(subject).authority()));
    }
    bindingAccountOperations = Map.copyOf(primaryOperations);
    var peerOperations = new TreeMap<String, List<OperationGrant>>();
    if (config.has("peerDelegationPolicies")) for (var peer : config.path("peerDelegationPolicies"))
      peerOperations.put(text(peer, "id", 255, false), operations(peer, "TENANT_PEER"));
    peerAccountOperations = Map.copyOf(peerOperations);
    adoptedAccounts = adoptions(config);
    workflowOperations = new WorkflowOperations(config, profiles.keySet());
  }

  private Map<String, PeerPolicy> peerPolicies(JsonNode config) {
    if (!config.has("peerDelegationPolicies")) return Map.of();
    var configured = config.path("peerDelegationPolicies");
    if (!configured.isArray() || configured.size() > 100) bad();
    var result = new TreeMap<String, PeerPolicy>();
    var sources = new HashSet<Map.Entry<String, Long>>();
    for (var entry : configured) {
      fields(without(entry, "accountOperations"), "id", "version", "sourceProfileId", "sourceProfileVersion", "humanClientIds",
          "audienceSets", "protectedProfileIds", "realmRoles", "clientRoles");
      String id = text(entry, "id", 255, false);
      long version = number(entry, "version", true);
      String sourceId = text(entry, "sourceProfileId", 255, false);
      long sourceVersion = number(entry, "sourceProfileVersion", true);
      var source = profiles.get(sourceId);
      if (source == null || !"TENANT_ADMIN".equals(source.kind()) || source.version() != sourceVersion
          || !sources.add(Map.entry(sourceId, sourceVersion))) bad();
      var clients = HumanPolicyJson.strings(entry.get("humanClientIds"), 1, 30, 255);
      if (!Collections.disjoint(clients, CurrentNativeHumanIdentity.ROUTINE_CLIENTS.values())) bad();
      var audiences = HumanPolicyJson.audiences(entry.get("audienceSets"));
      var targets = HumanPolicyJson.strings(entry.get("protectedProfileIds"), 1, 100, 255);
      for (String targetId : targets) {
        var target = profiles.get(targetId);
        if (target == null || !"TENANT_ADMIN".equals(target.kind()) || !target.modes().contains("EXISTING")) bad();
      }
      var roles = HumanPolicyJson.strings(entry.get("realmRoles"), 1, 100, 255);
      var clientRoles = HumanPolicyJson.clientRoles(entry.get("clientRoles"));
      if (!source.realmRoles().equals(roles) || !source.clientRoles().equals(clientRoles)) bad();
      var common = JSON.createObjectNode();
      for (String name : List.of("realmId", "issuer", "technicalSubjects", "technicalGroupIds", "technicalRoles"))
        common.set(name, config.get(name));
      common.set("clientIds", entry.get("humanClientIds"));
      common.set("audienceSets", entry.get("audienceSets"));
      var nativePolicy = CurrentNativeHumanIdentity.nativePolicy(common);
      if (result.put(id, new PeerPolicy(id, version, sourceId, sourceVersion, clients, audiences, targets,
          roles, clientRoles, nativePolicy, without(entry, "accountOperations"))) != null) bad();
    }
    return Map.copyOf(result);
  }

  private List<OperationGrant> operations(JsonNode owner, String authority) {
    if (!owner.has("accountOperations")) return List.of();
    var configured = owner.path("accountOperations");
    if (!configured.isArray() || configured.size() > 20) bad();
    var result = new ArrayList<OperationGrant>();
    var unique = new HashSet<OperationGrant>();
    for (var grant : configured) {
      fields(without(grant, "targetSubjects"), "authority", "targetProfiles", "operations", "selfOnly");
      if (!authority.equals(text(grant, "authority", 20, false)) || !grant.path("selfOnly").isBoolean()) bad();
      var targets = HumanPolicyJson.strings(grant.get("targetProfiles"), 1, 100, 255);
      for (String id : targets) {
        var profile = profiles.get(id);
        if (profile == null || "TENANT_PEER".equals(authority)
            && (!"TENANT_ADMIN".equals(profile.kind()) || !profile.modes().contains("EXISTING"))) bad();
      }
      var selected = HumanPolicyJson.strings(grant.get("operations"), 1, ACCOUNT_OPERATIONS.size(), 80);
      if (!ACCOUNT_OPERATIONS.containsAll(selected)) bad();
      if (selected.contains("account.reassign-tenant") && (!"PLATFORM".equals(authority)
          || grant.path("selfOnly").booleanValue()
          || targets.stream().anyMatch(id -> !"TENANT_ADMIN".equals(profiles.get(id).kind())))) bad();
      var subjects = grant.has("targetSubjects")
          ? HumanPolicyJson.strings(grant.get("targetSubjects"), 0, 1000, 36) : Set.<String>of();
      for (String subject : subjects) uuid(subject);
      var parsed = new OperationGrant(authority, targets, selected, grant.path("selfOnly").booleanValue(), subjects);
      if (!unique.add(parsed)) bad();
      result.add(parsed);
    }
    return List.copyOf(result);
  }

  private Map<String, Adoption> adoptions(JsonNode config) {
    if (!config.has("adoptedAccounts")) return Map.of();
    var configured = config.path("adoptedAccounts");
    if (!configured.isArray() || configured.size() > 1000) bad();
    var result = new TreeMap<String, Adoption>();
    for (var entry : configured) {
      fields(entry, "accountId", "protectedProfileId", "profileVersion");
      String account = uuid(text(entry, "accountId", 36, false));
      String profileId = text(entry, "protectedProfileId", 255, false);
      long version = number(entry, "profileVersion", true);
      var profile = profiles.get(profileId);
      if (profile == null || profile.version() != version
          || result.put(account, new Adoption(account, profileId, version)) != null) bad();
    }
    return Map.copyOf(result);
  }

  private static JsonNode without(JsonNode value, String... optional) {
    var copy = value.deepCopy();
    if (copy.isObject()) for (String name : optional)
      ((com.fasterxml.jackson.databind.node.ObjectNode) copy).remove(name);
    return copy;
  }

  void validateInstallation(KeycloakSession session) {
    if (!realmId.equals(session.getContext().getRealm().getId()) || !realmName.equals(session.getContext().getRealm().getName())) deny();
    for (var binding : bindings.values()) CurrentHumanAuthorization.validateInstallation(session, binding.policy());
    if (!actors.equals(CurrentNativeHumanIdentity.currentRoutineSubjects(CurrentNativeHumanIdentity.entityManager(session), realmId))) deny();
    for (var peer : peerPolicies.values()) CurrentNativeHumanIdentity.validateInstallation(session, peer.nativePolicy());
    for (var profile : profiles.values()) validateProfile(session, profile);
  }

  void validateProfile(KeycloakSession session, Profile profile) {
    var graph = NativeCurrentGrants.read(CurrentNativeHumanIdentity.entityManager(session), realmId, Set.of(), Set.of(profile.groupId()));
    if (!profile.groupPath().equals(graph.paths().get(profile.groupId()))
        || !profile.realmRoles().equals(graph.realmRoles()) || !profile.clientRoles().equals(graph.clientRoles())) deny();
    for (var technical : installation.path("technicalGroupIds")) if (graph.groups().containsKey(technical.asText())) deny();
  }
}
