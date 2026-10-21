package org.oriso.keycloak.lifecycle;

import java.util.*;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.services.resource.*;

/** Standalone provider; absent/false enable flag does not register a resource. */
public final class AccountLifecycleFactory implements RealmResourceProviderFactory {
  private LifecycleAuthorization authorization;
  private Map<String, Set<String>> groups;
  private GeneralPolicy humanPolicy;

  public void init(Config.Scope scope) {
    String enabled = System.getenv("ORISO_ACCOUNT_LIFECYCLE_ENABLED");
    if (enabled == null || "false".equals(enabled)) return;
    if (!"true".equals(enabled) || !"FIVE_ACTORS".equals(System.getenv("TASK_IDENTITY_MODEL")))
      throw new IllegalStateException("Invalid lifecycle enable/model configuration");
    String realm = required("ORISO_ACCOUNT_LIFECYCLE_REALM");
    String creator = required("IDENTITY_ACCOUNT_CREATE_SERVICE_SUBJECT");
    String admin = required("IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT");
    if (creator.equals(admin))
      throw new IllegalStateException("Lifecycle actor subjects must differ");
    String encoded = required("ORISO_TASK_CONTEXT_KEY");
    byte[] key;
    try {
      key = Base64.getDecoder().decode(encoded);
    } catch (IllegalArgumentException failure) {
      throw new IllegalStateException("Lifecycle key must be base64");
    }
    if (key.length < 32)
      throw new IllegalStateException("Lifecycle key must contain at least 32 bytes");
    groups = new LinkedHashMap<>();
    var config = LifecycleJson.parse(required("ORISO_ACCOUNT_LIFECYCLE_GROUPS"));
    config
        .fields()
        .forEachRemaining(
            entry -> {
              if (!entry.getKey().matches("/human-roles/[a-z0-9-]{1,80}")
                  || !entry.getValue().isArray()
                  || entry.getValue().isEmpty()
                  || entry.getValue().size() > 5)
                throw new IllegalStateException("Invalid ordinary lifecycle mapping");
              Set<String> roles = new HashSet<>();
              entry
                  .getValue()
                  .forEach(
                      role -> {
                        if (!role.isTextual()
                            || !LifecycleGroups.KNOWN.contains(role.asText())
                            || !roles.add(role.asText()))
                          throw new IllegalStateException(
                              "Invalid ordinary lifecycle role mapping");
                      });
              if (LifecycleGroups.allowedKind(roles) == null)
                throw new IllegalStateException("Unknown ordinary lifecycle combination");
              groups.put(entry.getKey(), Set.copyOf(roles));
            });
    if (groups.isEmpty()) throw new IllegalStateException("Missing ordinary lifecycle mappings");
    authorization = new LifecycleAuthorization(realm, creator, admin, key, encoded);
    String humanConfig = System.getenv("ORISO_ACCOUNT_MAINTENANCE_CONFIG");
    if (humanConfig != null) humanPolicy = new GeneralPolicy(LifecycleJson.parse(humanConfig));
  }

  private static String required(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank() || value.contains("${"))
      throw new IllegalStateException("Missing lifecycle configuration: " + name);
    return value;
  }

  public RealmResourceProvider create(KeycloakSession session) {
    return authorization == null
        ? null
        : new AccountLifecycleResource(session, authorization, groups);
  }

  // Both finite providers share exactly the same trusted configuration parser.
  RealmResourceProvider createMaintenance(KeycloakSession session) {
    return authorization == null
        ? null
        : new AccountMaintenanceResource(session, authorization, groups, humanPolicy);
  }

  public String getId() {
    return "oriso-account-lifecycle";
  }

  public void postInit(KeycloakSessionFactory factory) {
    if (humanPolicy == null) return;
    factory.register(event -> {
      if (event instanceof org.keycloak.models.utils.PostMigrationEvent)
        org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction(factory, session -> {
          var realm = session.realms().getRealm(humanPolicy.nativePolicy.realmId);
          if (realm == null) throw new IllegalStateException("Ordinary human native realm is missing");
          session.getContext().setRealm(realm);
          humanPolicy.validateInstallation(session);
        });
    });
  }

  jakarta.ws.rs.core.Response readOtpSelf(KeycloakSession session, String username,
      String targetHeader, String proofHeader, String humanHeader,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> read) {
    if (authorization == null) LifecycleJson.deny();
    return ScopedOtpAccess.checkedSelfRead(session, authorization, groups, humanPolicy,
        username, targetHeader, proofHeader, humanHeader, read);
  }

  jakarta.ws.rs.core.Response appSetupOtpSelf(KeycloakSession session, String username,
      byte[] raw, String proofHeader, String humanHeader,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> setup) {
    if (authorization == null) LifecycleJson.deny();
    return ScopedOtpAccess.checkedSelfMutation(session, authorization, groups, humanPolicy,
        "otp.app-setup", "PUT", username, raw, proofHeader, humanHeader, setup);
  }

  jakarta.ws.rs.core.Response deleteOtpSelf(KeycloakSession session, String username,
      byte[] raw, String proofHeader, String humanHeader,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> delete) {
    if (authorization == null) LifecycleJson.deny();
    return ScopedOtpAccess.checkedSelfMutation(session, authorization, groups, humanPolicy,
        "otp.delete", "DELETE", username, raw, proofHeader, humanHeader, delete);
  }

  public void close() {}
}
