package org.oriso.keycloak.commands;

import java.util.List;
import org.keycloak.Config.Scope;
import org.keycloak.connections.jpa.entityprovider.*;
import org.keycloak.models.*;

public final class CommandEntities implements JpaEntityProviderFactory {
  public JpaEntityProvider create(KeycloakSession session) {
    return new JpaEntityProvider() {
      public List<Class<?>> getEntities() {
        return List.of(CreationAttempt.class, SmtpRevision.class);
      }

      public String getChangelogLocation() {
        return "META-INF/oriso-task-commands-changelog.xml";
      }

      public String getFactoryId() {
        return "oriso-task-command-entities";
      }

      public void close() {}
    };
  }

  public String getId() {
    return "oriso-task-command-entities";
  }

  public void init(Scope scope) {}

  public void postInit(KeycloakSessionFactory factory) {}

  public void close() {}
}
