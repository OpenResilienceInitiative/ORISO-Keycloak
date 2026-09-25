package de.onlineberatung.authenticator;

import static java.util.Objects.isNull;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import java.util.Set;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator;

public class BearerTokenSessionAuthenticator implements SessionAuthenticator {

  /** Held only by the backend Keycloak admin identity (ORISO-Helm#367). */
  static final String OTP_CONFIG_ADMIN_ROLE = "otp-config-admin";

  private static final Set<String> ALLOWED_ROLES = Set.of(OTP_CONFIG_ADMIN_ROLE);

  @Override
  public void authenticate(KeycloakSession session) {
    var auth = new BearerTokenAuthenticator(session).authenticate();
    if (auth == null) {
      throw new NotAuthorizedException("Bearer");
    }
    requireAllowedRole(auth.getUser());
  }

  /** Direct realm-role mappings only, so a composite or group cannot grant this by accident. */
  static void requireAllowedRole(UserModel user) {
    if (isNull(user)
        || user.getRoleMappingsStream().map(RoleModel::getName).noneMatch(ALLOWED_ROLES::contains)) {
      throw new ForbiddenException("Does not have required role");
    }
  }
}
