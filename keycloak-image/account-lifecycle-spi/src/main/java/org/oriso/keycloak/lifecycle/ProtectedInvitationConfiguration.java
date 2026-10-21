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

  record Binding(String authority, Set<Long> tenants, Set<String> profiles, CurrentHumanAuthorization.Policy policy) {}
  record Profile(String id, long version, String kind, Set<String> modes, String groupId, String groupPath,
      Set<String> realmRoles, Map<String, Set<String>> clientRoles, JsonNode snapshot) {}

  ProtectedInvitationConfiguration(JsonNode config) {
    fields(config, "realmId", "realmName", "issuer", "technicalSubjects", "technicalGroupIds", "technicalRoles",
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
      fields(binding, "subject", "authority", "authorizerTenantIds", "humanClientIds", "audienceSets", "protectedProfileIds", "realmRoles", "clientRoles", "version");
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
  }

  void validateInstallation(KeycloakSession session) {
    if (!realmId.equals(session.getContext().getRealm().getId()) || !realmName.equals(session.getContext().getRealm().getName())) deny();
    for (var binding : bindings.values()) CurrentHumanAuthorization.validateInstallation(session, binding.policy());
    for (var profile : profiles.values()) validateProfile(session, profile);
  }

  void validateProfile(KeycloakSession session, Profile profile) {
    var graph = NativeCurrentGrants.read(CurrentNativeHumanIdentity.entityManager(session), realmId, Set.of(), Set.of(profile.groupId()));
    if (!profile.groupPath().equals(graph.paths().get(profile.groupId()))
        || !profile.realmRoles().equals(graph.realmRoles()) || !profile.clientRoles().equals(graph.clientRoles())) deny();
    for (var technical : installation.path("technicalGroupIds")) if (graph.groups().containsKey(technical.asText())) deny();
  }
}
