package org.oriso.keycloak.lifecycle;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Finite maintenance receiver, enabled only with the existing default-off lifecycle contract. */
public final class AccountMaintenanceFactory implements RealmResourceProviderFactory {
  private final AccountLifecycleFactory configuration = new AccountLifecycleFactory();

  public void init(Config.Scope scope) { configuration.init(scope); }
  public RealmResourceProvider create(KeycloakSession session) {
    return configuration.createMaintenance(session);
  }
  public String getId() { return "oriso-account-maintenance"; }
  public void postInit(KeycloakSessionFactory factory) {}
  public void close() {}
}
