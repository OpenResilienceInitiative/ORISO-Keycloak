package de.onlineberatung.authenticator;

import org.keycloak.models.KeycloakSession;
import org.oriso.keycloak.auth.TaskIdentity;

/** Shared exact task boundary; legacy OTP compatibility is explicit and temporary. */
public class BearerTokenSessionAuthenticator implements SessionAuthenticator {
  @Override
  public void authenticate(KeycloakSession session) {
    TaskIdentity.requireOtp(session);
  }
}
