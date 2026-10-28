package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;
import org.keycloak.models.KeycloakSession;

/** Exact independently installed privileged human binding, separate from ordinary policies. */
public final class CurrentHumanAuthorization {
  public static Policy policy(JsonNode config) {
    fields(config, "realmId", "subject", "issuer", "tenantIds", "clientIds", "audienceSets",
        "realmRoles", "clientRoles", "technicalSubjects", "technicalGroupIds", "technicalRoles", "version");
    return new Policy(config);
  }

  public static final class Policy {
    final String subject;
    final long version;
    final Set<Long> tenants;
    final Set<String> realmRoles;
    final Map<String, Set<String>> clientRoles;
    final CurrentNativeHumanIdentity.NativePolicy nativePolicy;
    private Policy(JsonNode config) {
      subject = uuid(text(config, "subject", 36, false));
      version = number(config, "version", true);
      tenants = HumanPolicyJson.tenants(config.get("tenantIds"));
      realmRoles = HumanPolicyJson.strings(config.get("realmRoles"), 1, 100, 255);
      clientRoles = HumanPolicyJson.clientRoles(config.get("clientRoles"));
      var common = JSON.createObjectNode();
      for (String key : List.of("realmId", "issuer", "clientIds", "audienceSets", "technicalSubjects", "technicalGroupIds", "technicalRoles"))
        common.set(key, config.get(key));
      nativePolicy = CurrentNativeHumanIdentity.nativePolicy(common);
      if (nativePolicy.subjects.contains(subject) || !Collections.disjoint(realmRoles, nativePolicy.technicalRoles)
          || clientRoles.containsKey("realm-management")) bad();
    }
  }

  public static void validateInstallation(KeycloakSession session, Policy policy) {
    validateInstallation(session, policy, null);
  }

  static void validatePrimaryInstallation(KeycloakSession session, ProtectedInvitationConfiguration config,
      ProtectedInvitationConfiguration.Binding binding) {
    requirePrimaryBinding(config, binding);
    validateInstallation(session, binding.policy(), config);
  }

  private static void validateInstallation(KeycloakSession session, Policy policy,
      ProtectedInvitationConfiguration config) {
    CurrentNativeHumanIdentity.validateInstallation(session, policy.nativePolicy);
    var em = CurrentNativeHumanIdentity.entityManager(session);
    var user = AccountLifecycleResource.lockedSnapshot(em, policy.subject);
    if (!policy.nativePolicy.realmId.equals(user.path("realmId").asText()) || !user.path("enabled").asBoolean()
        || !user.path("serviceAccountClientLink").isNull() || !user.path("federationLink").isNull()) deny();
    var nativeTenant = user.path("attributes").get("tenantId");
    if (nativeTenant == null || nativeTenant.size() != 1 || !nativeTenant.get(0).isTextual()
        || !nativeTenant.get(0).asText().matches("0|[1-9][0-9]{0,18}")) deny();
    try { if (!policy.tenants.contains(Long.valueOf(nativeTenant.get(0).asText()))) deny(); }
    catch (NumberFormatException failure) { deny(); }
    var roleIds = new TreeSet<String>();
    user.path("roles").forEach(value -> roleIds.add(value.asText()));
    var groupIds = new TreeSet<String>();
    user.path("groups").forEach(value -> groupIds.add(value.asText()));
    var grants = NativeCurrentGrants.read(em, policy.nativePolicy.realmId, roleIds, groupIds);
    if (!Collections.disjoint(grants.groups().keySet(), policy.nativePolicy.groups)
        || !matchesPrimary(session, config, policy, user, grants.realmRoles(), grants.clientRoles())) deny();
  }

  static VerifiedHuman requirePrimary(KeycloakSession session, ProtectedInvitationConfiguration config,
      ProtectedInvitationConfiguration.Binding binding, String rawHumanBearer) {
    requirePrimaryBinding(config, binding);
    var policy = binding.policy();
    var human = rawHumanBearer == null ? CurrentNativeHumanIdentity.require(session, policy.nativePolicy)
        : CurrentNativeHumanIdentity.require(session, policy.nativePolicy, rawHumanBearer);
    if (!policy.subject.equals(human.subject()) || human.tenantId() == null || !policy.tenants.contains(human.tenantId())) deny();
    var user = AccountLifecycleResource.lockedSnapshot(CurrentNativeHumanIdentity.entityManager(session), human.subject());
    if (!matchesPrimary(session, config, policy, user, human.realmRoles(), human.clientRoles())) deny();
    return new VerifiedHuman(human, policy.version);
  }

  private static void requirePrimaryBinding(ProtectedInvitationConfiguration config,
      ProtectedInvitationConfiguration.Binding binding) {
    if (config.bindings.get(binding.policy().subject) != binding) deny();
  }

  private static boolean matchesPrimary(KeycloakSession session, ProtectedInvitationConfiguration config,
      Policy policy, JsonNode user, Set<String> roles, Map<String, Set<String>> clientRoles) {
    if (policy.realmRoles.equals(roles) && policy.clientRoles.equals(clientRoles)) return true;
    if (config == null || !user.path("roles").isEmpty() || user.path("groups").size() != 1) return false;
    for (var profile : config.sourceProfileVariants.getOrDefault(policy.subject, List.of())) {
      if (!profile.groupId().equals(user.path("groups").path(0).asText())
          || !profile.realmRoles().equals(roles) || !profile.clientRoles().equals(clientRoles)) continue;
      config.validateProfile(session, profile);
      return true;
    }
    return false;
  }

  public static VerifiedHuman require(KeycloakSession session, Policy policy) {
    return checked(policy, CurrentNativeHumanIdentity.require(session, policy.nativePolicy));
  }

  public static VerifiedHuman require(KeycloakSession session, Policy policy, String rawHumanBearer) {
    return checked(policy, CurrentNativeHumanIdentity.require(session, policy.nativePolicy, rawHumanBearer));
  }

  private static VerifiedHuman checked(Policy policy, CurrentNativeHumanIdentity.VerifiedHuman human) {
    if (!policy.subject.equals(human.subject()) || human.tenantId() == null || !policy.tenants.contains(human.tenantId())
        || !policy.realmRoles.equals(human.realmRoles()) || !policy.clientRoles.equals(human.clientRoles())) deny();
    return new VerifiedHuman(human, policy.version);
  }

  public static final class VerifiedHuman {
    private final CurrentNativeHumanIdentity.VerifiedHuman human;
    private final long policyVersion;
    private VerifiedHuman(CurrentNativeHumanIdentity.VerifiedHuman human, long version) { this.human = human; policyVersion = version; }
    public String realmId() { return human.realmId(); }
    public String subject() { return human.subject(); }
    public long tenantId() { return human.tenantId(); }
    public String clientId() { return human.clientId(); }
    public String issuer() { return human.issuer(); }
    public long policyVersion() { return policyVersion; }
    public long validatedJwtExpiresAt() { return human.validatedJwtExpiresAt(); }
    public Set<String> realmRoles() { return human.realmRoles(); }
    public Map<String, Set<String>> clientRoles() { return human.clientRoles(); }
  }

  private CurrentHumanAuthorization() {}
}
