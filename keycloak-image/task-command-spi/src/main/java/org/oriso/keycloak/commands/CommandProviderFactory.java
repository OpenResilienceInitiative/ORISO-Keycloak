package org.oriso.keycloak.commands;

import org.keycloak.Config.Scope;
import org.keycloak.models.*;
import org.keycloak.services.resource.*;
import org.oriso.keycloak.auth.OriginAuthorization;

public final class CommandProviderFactory implements RealmResourceProviderFactory {
  private OriginAuthorization origins;

  public RealmResourceProvider create(KeycloakSession session) {
    return new CommandResource(session, origins);
  }

  public String getId() {
    return "oriso-commands";
  }

  public void init(Scope scope) {
    origins = new OriginAuthorization();
  }

  public void postInit(KeycloakSessionFactory factory) {}

  public void close() {}
}
