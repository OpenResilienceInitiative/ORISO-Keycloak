package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Set;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

/** Actual current SELF over independently checked ordinary or protected native provenance. */
final class SelfAccountOperations {
  static JsonNode current(KeycloakSession session, LifecycleAuthorization crypto, MaintenanceTarget targets,
      GeneralPolicy policy, MaintenanceRequest request, String human) {
    if (!"SELF".equals(request.target().path("origin").path("kind").asText()) || request.workflow() != null
        || !Set.of("profile", "email", "locale", "password", "self-password").contains(request.command())) deny();
    boolean combined = "email".equals(request.command()) && request.change().has("firstName");
    if (ProtectedAccountOperations.selected(request.target())) {
      if (!ProtectedAccountOperations.protectedTarget(session, request)) deny();
      var current = ProtectedAccountOperations.readAccount(session, crypto, request, human);
      String operation = "account." + ("self-password".equals(request.command()) ? "password" : request.command());
      ProtectedAccountOperations.readSelfOperation(session, crypto, request, human, operation);
      if (combined) ProtectedAccountOperations.readSelfOperation(session, crypto, request, human, "account.profile");
      return current;
    }
    if (policy == null) deny();
    // Native provenance locks precede the additional fresh-human grant checks.
    var current = targets.read(request, policy, human);
    policy.requireSelfRead(session, request, human);
    if (combined) policy.requireSelfProfile(session, request, human);
    return current;
  }

  static void mutate(KeycloakSession session, LifecycleAuthorization crypto, MaintenanceTarget targets,
      GeneralPolicy policy, MaintenanceRequest request, String human) {
    var current = current(session, crypto, targets, policy, request, human);
    if (!LifecycleAuthorization.equal(request.expectedState(), current.path("state").asText()))
      throw MaintenancePreflightRefusal.current(409);
    if ("profile".equals(request.command()) && !request.change().path("email").equals(current.path("email"))) deny();
    var realm = session.getContext().getRealm();
    var user = session.users().getUserById(realm, request.accountId());
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) { cache.evict(realm, user); user = session.users().getUserById(realm, request.accountId()); }
    if (user == null) throw MaintenancePreflightRefusal.current(409);
    if (Set.of("password", "self-password").contains(request.command())) {
      password(session, request, user);
      return;
    }
    switch (request.command()) {
      case "locale" -> user.setSingleAttribute("locale", request.change().path("locale").textValue());
      case "profile" -> names(user, request.change());
      case "email" -> {
        if (request.change().has("firstName")) names(user, request.change());
        user.setEmail(request.change().path("email").textValue());
        // The existing SELF profile caller attests its checked profile email, not mail possession.
        user.setEmailVerified(true);
      }
      default -> deny();
    }
    var em = CurrentNativeHumanIdentity.entityManager(session); em.flush();
    if ("locale".equals(request.command())) {
      var values = em.createNativeQuery("select VALUE, LONG_VALUE from USER_ATTRIBUTE where USER_ID=:account and NAME='locale' for update")
          .setParameter("account", request.accountId()).getResultList();
      if (values.size() != 1) throw new IllegalStateException("Native SELF locale did not complete");
      var value = (Object[]) values.get(0);
      Object stored = value[0];
      if (stored instanceof java.sql.Clob clob) {
        try { stored = clob.getSubString(1, Math.toIntExact(clob.length())); }
        catch (java.sql.SQLException failure) { throw new IllegalStateException("Native SELF locale unavailable"); }
      }
      if (!request.change().path("locale").asText().equals(stored) || value[1] != null)
        throw new IllegalStateException("Native SELF locale did not complete");
    } else {
      var fresh = AccountLifecycleResource.lockedSnapshot(em, request.accountId());
      for (String field : List.of("firstName", "lastName", "email"))
        if (request.change().has(field) && !request.change().path(field).equals(fresh.path(field)))
          throw new IllegalStateException("Native SELF profile did not complete");
      if ("email".equals(request.command()) && !fresh.path("emailVerified").asBoolean())
        throw new IllegalStateException("Native SELF email did not complete");
    }
  }

  private static void names(UserModel user, JsonNode change) {
    user.setFirstName(change.path("firstName").isNull() ? null : change.path("firstName").textValue());
    user.setLastName(change.path("lastName").isNull() ? null : change.path("lastName").textValue());
  }

  private static void password(KeycloakSession session, MaintenanceRequest request, UserModel user) {
    if (request.change().path("temporary").asBoolean()) deny();
    if ("self-password".equals(request.command()) && !verifyCurrent(session, user, request.change().path("currentPassword").textValue()))
      throw new jakarta.ws.rs.BadRequestException("Current password was not accepted");
    String password = request.change().path("password").textValue();
    if (session.getProvider(org.keycloak.policy.PasswordPolicyManagerProvider.class)
        .validate(session.getContext().getRealm(), user, password) != null) {
      if ("self-password".equals(request.command())) throw MaintenancePreflightRefusal.passwordPolicy(request);
      bad();
    }
    request.requireEffectDeadline();
    try {
      if (!user.credentialManager().updateCredential(UserCredentialModel.password(password))) bad();
      user.removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
      CurrentNativeHumanIdentity.entityManager(session).flush();
    } catch (org.keycloak.models.ModelException invalid) {
      // A provider failure during the actual effect is never a definite pre-write receipt.
      throw new jakarta.ws.rs.BadRequestException("Password validation failed");
    }
  }

  private static boolean verifyCurrent(KeycloakSession session, UserModel user, String supplied) {
    // Match PasswordCredentialProvider.getPassword's first stored password selection. Its isValid
    // callback can enqueue an old-password rehash after COMMIT, so it cannot precede a password write.
    try (var credentials = user.credentialManager().getStoredCredentialsByTypeStream(PasswordCredentialModel.TYPE)) {
      var stored = credentials.findFirst().orElse(null);
      if (stored == null) return false;
      var password = PasswordCredentialModel.createFromCredentialModel(stored);
      String algorithm = password.getPasswordCredentialData().getAlgorithm();
      if (algorithm == null || algorithm.isBlank()) return false;
      var provider = session.getProvider(PasswordHashProvider.class, algorithm);
      if (provider == null) return false;
      try { return provider.verify(supplied, password); }
      catch (RuntimeException invalid) { return false; }
    }
  }

  private SelfAccountOperations() {}
}
