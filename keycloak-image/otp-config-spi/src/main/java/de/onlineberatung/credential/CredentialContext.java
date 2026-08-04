package de.onlineberatung.credential;

import java.util.Objects;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class CredentialContext {

  private final KeycloakSession session;
  private final RealmModel realm;
  private final UserModel user;

  public CredentialContext(KeycloakSession session, RealmModel realm, UserModel user) {
    this.session = session;
    this.realm = realm;
    this.user = user;
  }

  public static CredentialContext fromAuthFlow(AuthenticationFlowContext context) {
    return new CredentialContext(context.getSession(), context.getRealm(), context.getUser());
  }

  public KeycloakSession getSession() {
    return session;
  }

  public RealmModel getRealm() {
    return realm;
  }

  public UserModel getUser() {
    return user;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CredentialContext that = (CredentialContext) o;
    return Objects.equals(session, that.session) && Objects.equals(realm,
        that.realm) && Objects.equals(user, that.user);
  }

  @Override
  public int hashCode() {
    return Objects.hash(session, realm, user);
  }
}
