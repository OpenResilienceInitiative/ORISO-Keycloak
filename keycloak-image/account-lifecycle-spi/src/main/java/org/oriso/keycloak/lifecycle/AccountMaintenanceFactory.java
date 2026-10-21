package org.oriso.keycloak.lifecycle;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Finite maintenance receiver, enabled only with the existing default-off lifecycle contract. */
public final class AccountMaintenanceFactory implements RealmResourceProviderFactory {
  private final AccountLifecycleFactory configuration = new AccountLifecycleFactory();

  private GeneralPolicy humanPolicy;

  public void init(Config.Scope scope) {
    configuration.init(scope);
    String value = System.getenv("ORISO_ACCOUNT_MAINTENANCE_CONFIG");
    if ("true".equals(System.getenv("ORISO_ACCOUNT_LIFECYCLE_ENABLED")) && value != null)
      humanPolicy = new GeneralPolicy(LifecycleJson.parse(value));
  }
  public RealmResourceProvider create(KeycloakSession session) {
    return configuration.createMaintenance(session, humanPolicy);
  }
  public String getId() { return "oriso-account-maintenance"; }
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
  public void close() {}
}
