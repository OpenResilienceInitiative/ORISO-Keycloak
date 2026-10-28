package org.oriso.keycloak.lifecycle;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.connections.jpa.entityprovider.*;
import org.keycloak.models.*;

public final class MagicLinkEntities implements JpaEntityProviderFactory {
  public JpaEntityProvider create(KeycloakSession session) {
    return new JpaEntityProvider() {
      public List<Class<?>> getEntities() { return List.of(MagicLinkSession.class); }
      public String getChangelogLocation() { return "META-INF/oriso-magic-link-changelog.xml"; }
      public String getFactoryId() { return "oriso-magic-link-entities"; }
      public void close() {}
    };
  }
  public String getId() { return "oriso-magic-link-entities"; }
  public void init(Config.Scope scope) {}
  public void postInit(KeycloakSessionFactory factory) {}
  public void close() {}
}
