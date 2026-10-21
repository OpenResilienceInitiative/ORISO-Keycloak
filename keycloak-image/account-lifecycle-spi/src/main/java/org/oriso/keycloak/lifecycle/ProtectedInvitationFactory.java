package org.oriso.keycloak.lifecycle;

import jakarta.ws.rs.ServiceUnavailableException;
import jakarta.ws.rs.core.Response;
import java.util.Base64;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.services.resource.*;

/** Default off; exact native installation is checked before exposing approval. */
public final class ProtectedInvitationFactory implements RealmResourceProviderFactory {
  private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger(ProtectedInvitationFactory.class.getName());
  private ProtectedInvitationConfiguration configuration;
  private LifecycleAuthorization authorization;
  private volatile boolean installationReady;

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
      if (!(event instanceof PostMigrationEvent)) return;
      installationReady = false;
      try {
        KeycloakModelUtils.runJobInTransaction(factory, session -> {
          var realm = session.realms().getRealm(configuration.realmId);
          if (realm == null) throw new IllegalStateException("Protected native realm is missing");
          session.getContext().setRealm(realm);
          configuration.validateInstallation(session);
        });
      } catch (RuntimeException failure) {
        LOG.warning("Protected invitation provider unavailable: native binding validation failed");
        return;
      }
      // Publish only after the validation transaction has committed successfully.
      installationReady = true;
    });
  }

  public RealmResourceProvider create(KeycloakSession session) {
    if (configuration == null) return null;
    if (!installationReady) {
      // Native error mapping rebuilds exception responses; set its request response too.
      session.getContext().getHttpResponse().setHeader("Cache-Control", "no-store");
      throw new ServiceUnavailableException(Response.status(503).header("Cache-Control", "no-store").build());
    }
    return new ProtectedInvitationResource(session, configuration, authorization);
  }
  public String getId() { return "oriso-protected-invitations"; }
  public void close() {}
}
