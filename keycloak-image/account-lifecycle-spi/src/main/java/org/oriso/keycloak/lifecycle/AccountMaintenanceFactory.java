package org.oriso.keycloak.lifecycle;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Finite maintenance receiver reuses the single installed lifecycle configuration. */
public final class AccountMaintenanceFactory implements RealmResourceProviderFactory {
  public void init(Config.Scope scope) {}
  public RealmResourceProvider create(KeycloakSession session) {
    var factory = session.getKeycloakSessionFactory().getProviderFactory(
        RealmResourceProvider.class, "oriso-account-lifecycle");
    if (!(factory instanceof AccountLifecycleFactory configuration)) return null;
    return configuration.createMaintenance(session);
  }
  public String getId() { return "oriso-account-maintenance"; }
  public void postInit(KeycloakSessionFactory factory) {}
  public void close() {}
}
