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
        || !policy.realmRoles.equals(grants.realmRoles()) || !policy.clientRoles.equals(grants.clientRoles())) deny();
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
