package de.onlineberatung.authenticator;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;

public interface SessionAuthenticator {

  void authenticate(KeycloakSession session);

  /** Legacy callers keep their existing target semantics. */
  default void authorizeTarget(KeycloakSession session, UserModel target) {
    // Default-off: target policy is supplied only by the C receiver.
  }

}
