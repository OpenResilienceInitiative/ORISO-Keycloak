package org.oriso.keycloak.auth;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.keycloak.models.*;
import org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

/** Exact receiving boundary shared by commands and OTP. */
public final class TaskIdentity {
  public static final String AUDIENCE = "oriso-task-commands";
  private static final Set<String> FORBIDDEN =
      Set.of(
          "technical",
          "user",
          "anonymous",
          "consultant",
          "group-chat-consultant",
          "restricted-agency-admin",
          "user-admin",
          "agency-admin",
          "tenant-admin",
          "topic-admin",
          "realm-admin",
          "impersonation",
          "cluster-admin");
  private static final Set<String> LEGACY_DIRECT_MANAGEMENT =
      Set.of("manage-users", "view-users", "query-users", "view-realm");
  // Verified native26.6.3 query-users composite adds query-groups to the issued token.
  private static final Set<String> LEGACY_EFFECTIVE_MANAGEMENT =
      Set.of("manage-users", "view-users", "query-users", "view-realm", "query-groups");

  public record Caller(
      String clientId,
      String subject,
      UserModel user,
      org.keycloak.representations.AccessToken token,
      ClientModel client) {}

  private TaskIdentity() {}

  public static String configured(String task) {
    String key = task.equals("account-otp") ? "OTP" : task.toUpperCase().replace('-', '_');
    String value = System.getenv("IDENTITY_" + key + "_CLIENT_ID");
    return value == null || value.isBlank() ? "backend-" + task : value;
  }

  public static Caller require(KeycloakSession session, String task, String role) {
    return verify(session, authenticate(session), configured(task), role, false);
  }

  public static Caller requireRead(KeycloakSession session) {
    AuthResult auth = authenticate(session);
    String client =
        configured("account-provisioning").equals(auth.getToken().getIssuedFor())
            ? configured("account-provisioning")
            : configured("account-maintenance");
    return verify(session, auth, client, "account-read", false);
  }

  public static Caller requireOtp(KeycloakSession session) {
    AuthResult auth = authenticate(session);
    String current = configured("account-otp");
    if (current.equals(auth.getToken().getIssuedFor()))
      return verify(session, auth, current, "otp-config-admin", false);
    String legacy = System.getenv().getOrDefault("ORISO_LEGACY_OTP_CLIENT_ID", "backend-admin");
    if (!"true".equals(System.getenv("ORISO_LEGACY_OTP_COMPATIBILITY"))
        || legacy.isBlank()
        || legacy.equals(current)) denied();
    return verify(session, auth, legacy, "otp-config-admin", true);
  }

  private static AuthResult authenticate(KeycloakSession session) {
    AuthResult auth = new BearerTokenAuthenticator(session).authenticate();
    if (auth == null) throw new NotAuthorizedException("Bearer");
    return auth;
  }

  private static Caller verify(
      KeycloakSession session,
      AuthResult auth,
      String clientId,
      String requiredRole,
      boolean legacy) {
    RealmModel realm = session.getContext().getRealm();
    ClientModel client = realm.getClientByClientId(clientId);
    var token = auth.getToken();
    if (client == null
        || !client.isEnabled()
        || !client.isServiceAccountsEnabled()
        || client.isPublicClient()
        || !clientId.equals(token.getIssuedFor())
        || token.getAudience() == null
        || !Arrays.asList(token.getAudience()).contains(legacy ? "realm-management" : AUDIENCE))
      denied();
    UserModel expected = session.users().getServiceAccount(client), actual = auth.getUser();
    if (expected == null
        || actual == null
        || !expected.isEnabled()
        || !expected.getId().equals(actual.getId())
        || !expected.getId().equals(token.getSubject())
        || !client.getId().equals(actual.getServiceAccountClientLink())) denied();
    if (actual
        .getRoleMappingsStream()
        .filter(role -> !role.isClientRole())
        .noneMatch(role -> requiredRole.equals(role.getName()) && !role.isComposite())) denied();
    if (token.getRealmAccess() == null
        || !token.getRealmAccess().isUserInRole(requiredRole)
        || token.getRealmAccess().getRoles().stream().anyMatch(FORBIDDEN::contains)) denied();
    for (String forbidden : FORBIDDEN) {
      RoleModel role = realm.getRole(forbidden);
      if (role != null && actual.hasRole(role)) denied();
    }
    if (legacy) {
      RoleModel defaults = realm.getDefaultRole();
      if (!token.getRealmAccess().getRoles().equals(Set.of(requiredRole))
          || actual.getGroupsStream().findAny().isPresent()) denied();
      if (actual
          .getRoleMappingsStream()
          .filter(role -> !role.isClientRole())
          .anyMatch(
              role ->
                  !role.getName().equals(requiredRole)
                      && (defaults == null || !role.getId().equals(defaults.getId())))) denied();
      if (defaults != null
          && actual.hasRole(defaults)
          && defaults.getCompositesStream().anyMatch(role -> !safeNativeDefault(role, realm)))
        denied();
      if (actual
          .getRoleMappingsStream()
          .filter(RoleModel::isClientRole)
          .anyMatch(
              role ->
                  !role.getContainerId()
                      .equals(realm.getClientByClientId("realm-management").getId()))) denied();
      if (Arrays.stream(token.getAudience())
          .anyMatch(audience -> !"realm-management".equals(audience))) denied();
      if (token.getResourceAccess().entrySet().stream()
          .anyMatch(
              entry ->
                  !entry.getKey().equals("realm-management")
                      && entry.getValue().getRoles() != null
                      && !entry.getValue().getRoles().isEmpty())) denied();
    }
    if (!legacy) {
      Set<String> permitted =
          clientId.equals(configured("account-provisioning"))
              ? Set.of("account-provisioning", "account-read")
              : clientId.equals(configured("account-maintenance"))
                  ? Set.of("account-maintenance", "account-read")
                  : Set.of(requiredRole);
      Set<String> direct =
          actual
              .getRoleMappingsStream()
              .filter(role -> !role.isClientRole())
              .map(RoleModel::getName)
              .collect(Collectors.toSet());
      if (!direct.equals(permitted)
          || actual
              .getRoleMappingsStream()
              .anyMatch(role -> role.isComposite() || role.isClientRole())
          || actual.getGroupsStream().findAny().isPresent()
          || !token.getRealmAccess().getRoles().equals(permitted)) denied();
      if (realm
          .getRolesStream()
          .anyMatch(role -> actual.hasRole(role) && !permitted.contains(role.getName()))) denied();
      Set<String> audiences =
          requiredRole.equals("smtp-sync")
              ? Set.of(AUDIENCE, "consultingtypeservice")
              : Set.of(AUDIENCE);
      if (Arrays.stream(token.getAudience()).anyMatch(audience -> !audiences.contains(audience)))
        denied();
      if (token.getResourceAccess().values().stream()
          .anyMatch(access -> access.getRoles() != null && !access.getRoles().isEmpty())) denied();
    }
    ClientModel management = realm.getClientByClientId("realm-management");
    if (management != null) {
      if (actual
          .getClientRoleMappingsStream(management)
          .anyMatch(role -> !legacy || !LEGACY_DIRECT_MANAGEMENT.contains(role.getName())))
        denied();
      if (management
          .getRolesStream()
          .anyMatch(
              role ->
                  actual.hasRole(role)
                      && (!legacy || !LEGACY_EFFECTIVE_MANAGEMENT.contains(role.getName()))))
        denied();
    }
    var managementAccess = token.getResourceAccess("realm-management");
    if (managementAccess != null
        && managementAccess.getRoles() != null
        && managementAccess.getRoles().stream()
            .anyMatch(role -> !legacy || !LEGACY_EFFECTIVE_MANAGEMENT.contains(role))) denied();
    if (token.getResourceAccess().values().stream()
        .anyMatch(
            access ->
                access.getRoles() != null
                    && access.getRoles().stream().anyMatch(FORBIDDEN::contains))) denied();
    return new Caller(clientId, token.getSubject(), actual, token, client);
  }

  private static boolean safeNativeDefault(RoleModel role, RealmModel realm) {
    if (!role.isClientRole())
      return !role.isComposite()
          && Set.of("offline_access", "uma_authorization").contains(role.getName());
    ClientModel account = realm.getClientByClientId("account");
    if (account == null || !account.getId().equals(role.getContainerId())) return false;
    if (Set.of("view-profile", "manage-account-links").contains(role.getName()))
      return !role.isComposite();
    return "manage-account".equals(role.getName())
        && role.getCompositesStream()
            .allMatch(
                child ->
                    child.isClientRole()
                        && !child.isComposite()
                        && account.getId().equals(child.getContainerId())
                        && child.getName().equals("manage-account-links"));
  }

  private static void denied() {
    throw new ForbiddenException("Task identity is not authorized");
  }
}
