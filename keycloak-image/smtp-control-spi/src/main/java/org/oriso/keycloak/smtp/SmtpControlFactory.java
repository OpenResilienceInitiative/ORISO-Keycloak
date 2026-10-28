package org.oriso.keycloak.smtp;

import java.util.Base64;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Standalone proposal; installing this factory never enables the resource by default. */
public final class SmtpControlFactory implements RealmResourceProviderFactory {
  private SmtpAuthorization authorization;

  @Override
  public void init(Config.Scope scope) {
    String enabled = System.getenv("ORISO_SMTP_CONTROL_ENABLED");
    if (enabled == null || "false".equals(enabled)) return;
    if (!"true".equals(enabled)) throw new IllegalStateException("Invalid SMTP control enable flag");
    String realm = required("ORISO_SMTP_CONTROL_REALM");
    String subject = required("IDENTITY_SETUP_SERVICE_SUBJECT");
    String encoded = required("ORISO_TASK_CONTEXT_KEY");
    byte[] key;
    try {
      key = Base64.getDecoder().decode(encoded);
    } catch (IllegalArgumentException failure) {
      throw new IllegalStateException("SMTP context key must be base64");
    }
    if (key.length < 32) throw new IllegalStateException("SMTP context key must contain at least 32 bytes");
    authorization = new SmtpAuthorization(realm, subject, key, encoded);
  }

  private static String required(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank() || value.contains("${"))
      throw new IllegalStateException("Missing SMTP control configuration: " + name);
    return value;
  }

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    return new SmtpControlResource(session, authorization);
  }

  @Override
  public String getId() { return "oriso-smtp-control"; }

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}
}
