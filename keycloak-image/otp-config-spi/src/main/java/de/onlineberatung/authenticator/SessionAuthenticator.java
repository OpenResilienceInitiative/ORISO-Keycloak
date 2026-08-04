package de.onlineberatung.authenticator;

import org.keycloak.models.KeycloakSession;

public interface SessionAuthenticator {

  void authenticate(KeycloakSession session);

}
