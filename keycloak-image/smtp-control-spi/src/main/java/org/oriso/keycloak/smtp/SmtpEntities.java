package org.oriso.keycloak.smtp;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider;
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public final class SmtpEntities implements JpaEntityProviderFactory {
  @Override
  public JpaEntityProvider create(KeycloakSession session) {
    return new JpaEntityProvider() {
      public List<Class<?>> getEntities() { return List.of(SmtpRevision.class); }
      public String getChangelogLocation() { return "META-INF/oriso-smtp-control-changelog.xml"; }
      public String getFactoryId() { return "oriso-smtp-control-entities"; }
      public void close() {}
    };
  }

  public String getId() { return "oriso-smtp-control-entities"; }
  public void init(Config.Scope scope) {}
  public void postInit(KeycloakSessionFactory factory) {}
  public void close() {}
}
