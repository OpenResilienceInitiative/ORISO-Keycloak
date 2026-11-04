package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.deny;

import jakarta.ws.rs.NotAuthorizedException;
import org.keycloak.models.ImpersonationSessionNote;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

/** Native authentication only; consumers separately authorize the checked current human. */
final class NativeHumanBearer {
  static AuthResult require(KeycloakSession session) {
    return authenticate(session, null, false);
  }

  static AuthResult require(KeycloakSession session, String rawBearer) {
    if (rawBearer == null || rawBearer.isBlank() || rawBearer.length() > 32768
        || rawBearer.chars().anyMatch(c -> c <= 32 || c == 127))
      throw new NotAuthorizedException("Bearer");
    return authenticate(session, rawBearer, true);
  }

  private static AuthResult authenticate(KeycloakSession session, String raw, boolean explicit) {
    var context = session.getContext();
    var previousClient = context.getClient();
    var previousBearer = context.getBearerToken();
    var previousSession = context.getUserSession();
    try {
      var authenticator = new BearerTokenAuthenticator(session);
      if (explicit) authenticator.setTokenString(raw);
      var checked = authenticator.authenticate();
      if (checked == null) throw new NotAuthorizedException("Bearer");
      var realm = context.getRealm();
      var token = checked.getToken();
      var user = checked.getUser();
      var client = checked.getClient();
      var humanSession = checked.getSession();
      if (realm == null || token == null || user == null || client == null
          || humanSession == null || humanSession.isOffline()
          || "impersonate".equals(humanSession.getAuthMethod())
          || !realm.isEnabled() || !user.isEnabled() || !client.isEnabled()
          || user.getServiceAccountClientLink() != null
          || !user.getId().equals(token.getSubject())
          || !user.getId().equals(humanSession.getUser().getId())
          || !realm.getId().equals(humanSession.getRealm().getId())
          || !client.getClientId().equals(token.getIssuedFor())
          || !humanSession.getId().equals(token.getSessionId())
          || !Urls.realmIssuer(context.getUri().getBaseUri(), realm.getName()).equals(token.getIssuer())) deny();
      // Native26.6.3 creates these notes on the impersonated target's session.
      // Being the target human is insufficient for that session to approve.
      for (var note : ImpersonationSessionNote.values()) {
        if (humanSession.getNote(note.name()) != null) deny();
      }
      var clientSession = humanSession.getAuthenticatedClientSessionByClient(client.getId());
      if (clientSession == null || !client.getId().equals(clientSession.getClient().getId())
          || !humanSession.getId().equals(clientSession.getUserSession().getId())) deny();
      return checked;
    } finally {
      // Keycloak26.6.3 verifyIdentityToken writes precisely these three fields.
      // A second human JWT must never replace the caller's saved machine identity.
      context.setClient(previousClient);
      context.setBearerToken(previousBearer);
      context.setUserSession(previousSession);
    }
  }

  private NativeHumanBearer() {}
}
