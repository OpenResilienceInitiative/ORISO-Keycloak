package org.oriso.keycloak.lifecycle;

import java.util.Base64;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.services.resource.*;

/** Default off; exact native installation is checked before exposing approval. */
public final class ProtectedInvitationFactory implements RealmResourceProviderFactory {
  private ProtectedInvitationConfiguration configuration;
  private LifecycleAuthorization authorization;

  public void init(Config.Scope scope) {
    String enabled = System.getenv("ORISO_PROTECTED_INVITATIONS_ENABLED");
    if (enabled == null || "false".equals(enabled)) return;
    if (!"true".equals(enabled) || !"FIVE_ACTORS".equals(System.getenv("TASK_IDENTITY_MODEL")))
      throw new IllegalStateException("Invalid protected invitation configuration");
    configuration = new ProtectedInvitationConfiguration(LifecycleJson.parse(required("ORISO_PROTECTED_INVITATIONS_CONFIG")));
    String encoded = required("ORISO_TASK_CONTEXT_KEY");
    byte[] key;
    try { key = Base64.getDecoder().decode(encoded); }
    catch (IllegalArgumentException failure) { throw new IllegalStateException("Invalid protected context key"); }
    if (key.length < 32) throw new IllegalStateException("Invalid protected context key");
    authorization = new LifecycleAuthorization(configuration.realmName, configuration.actors.get("ACCOUNT_CREATE"),
        configuration.actors.get("ACCOUNT_ADMIN"), key, encoded);
  }

  private static String required(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank() || value.contains("${")) throw new IllegalStateException("Missing protected invitation configuration");
    return value;
  }

  public void postInit(KeycloakSessionFactory factory) {
    if (configuration == null) return;
    factory.register(event -> {
      if (event instanceof PostMigrationEvent) KeycloakModelUtils.runJobInTransaction(factory, session -> {
        var realm = session.realms().getRealm(configuration.realmId);
        if (realm == null) throw new IllegalStateException("Protected native realm is missing");
        session.getContext().setRealm(realm);
        configuration.validateInstallation(session);
      });
    });
  }

  public RealmResourceProvider create(KeycloakSession session) {
    return configuration == null ? null : new ProtectedInvitationResource(session, configuration, authorization);
  }
  public String getId() { return "oriso-protected-invitations"; }
  public void close() {}
}
