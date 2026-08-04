package de.onlineberatung.log;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class LoggingEventListenerProviderFactory implements EventListenerProviderFactory {

  public static final String ID = "jboss-logging-without-ip-addresses";

  private static final Logger logger = Logger.getLogger("org.keycloak.ob.events");

  private Logger.Level successLevel;
  private Logger.Level errorLevel;

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    return new LoggingEventListenerProvider(session, logger, successLevel, errorLevel);
  }

  @Override
  public void init(Config.Scope config) {
    successLevel = Logger.Level.valueOf(config.get("success-level", "debug").toUpperCase());
    errorLevel = Logger.Level.valueOf(config.get("error-level", "warn").toUpperCase());
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // unused
  }

  @Override
  public void close() {
    // unused
  }

  @Override
  public String getId() {
    return ID;
  }
}
