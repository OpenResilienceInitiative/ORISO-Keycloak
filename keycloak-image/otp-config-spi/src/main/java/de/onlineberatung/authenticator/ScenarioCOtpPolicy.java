package de.onlineberatung.authenticator;

import jakarta.ws.rs.ForbiddenException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.keycloak.authorization.common.DefaultEvaluationContext;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.fgap.AdminPermissionsSchema;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.DecisionPermissionCollector;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.fgap.AdminPermissions;

/** Default-off receiver fence; caller and protected-human activation remain separate gates. */
public final class ScenarioCOtpPolicy {
  private static final Set<String> ROLES =
      Set.of("account-maintenance", "account-read", "otp-config-admin", "session-exchange");
  private static final Set<String> AUDIENCES = Set.of("oriso-otp", "userservice");
  private static final Set<String> PROTECTED_ROLES =
      Set.of(
          "tenant-admin",
          "super-admin",
          "platform-admin",
          "single-tenant-admin",
          "topic-admin",
          "global-support-admin",
          "realm-admin",
          "manage-users",
          "manage-realm");
  private final String subject;

  private ScenarioCOtpPolicy(String subject) {
    this.subject = subject;
  }

  public static ScenarioCOtpPolicy fromEnvironment(Function<String, String> environment) {
    String model = environment.apply("TASK_IDENTITY_MODEL");
    if (model == null || model.isBlank()) return null;
    if (!"FIVE_ACTORS".equals(model)) {
      throw new IllegalStateException("Unsupported OTP task identity model");
    }
    if (!"backend-account-admin".equals(environment.apply("IDENTITY_ACCOUNT_ADMIN_CLIENT_ID"))) {
      throw new IllegalStateException("C OTP requires the canonical ACCOUNT_ADMIN client");
    }
    String subject = environment.apply("IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT");
    try {
      if (subject == null || !UUID.fromString(subject).toString().equals(subject)) {
        throw new IllegalArgumentException();
      }
    } catch (IllegalArgumentException failure) {
      throw new IllegalStateException("C OTP requires a canonical service-account subject");
    }
    return new ScenarioCOtpPolicy(subject);
  }

  void requireActor(KeycloakSession session, AuthResult auth) {
    var realm = session.getContext().getRealm();
    var client = realm.getClientByClientId("backend-account-admin");
    var token = auth.getToken();
    var user = auth.getUser();
    if (client == null
        || !client.isEnabled()
        || client.isPublicClient()
        || !client.isServiceAccountsEnabled()
        || client.isStandardFlowEnabled()
        || client.isDirectAccessGrantsEnabled()
        || client.isFullScopeAllowed()
        || !"backend-account-admin".equals(token.getIssuedFor())
        || !Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName())
            .equals(token.getIssuer())
        || user == null
        || !user.isEnabled()
        || !subject.equals(user.getId())
        || !subject.equals(token.getSubject())
        || !client.getId().equals(user.getServiceAccountClientLink())
        || token.getAudience() == null
        || !Arrays.asList(token.getAudience()).contains("oriso-otp")
        || !AUDIENCES.containsAll(Arrays.asList(token.getAudience()))) denied();
    var expected = session.users().getServiceAccount(client);
    if (expected == null || !subject.equals(expected.getId())) denied();
    var groups = user.getGroupsStream().limit(2).collect(Collectors.toList());
    if (groups.size() != 1) denied();
    var technical = groups.get(0);
    var parent = technical.getParent();
    if (!"technical-identities".equals(technical.getName())
        || parent == null
        || !"protected-admins".equals(parent.getName())
        || parent.getParent() != null
        || technical.getRoleMappingsStream().findAny().isPresent()
        || parent.getRoleMappingsStream().findAny().isPresent()) denied();
    var direct = user.getRoleMappingsStream().collect(Collectors.toList());
    if (direct.stream().anyMatch(role -> role.isClientRole() || role.isComposite())
        || !direct.stream().map(RoleModel::getName).collect(Collectors.toSet()).equals(ROLES)
        || token.getRealmAccess() == null
        || !ROLES.equals(token.getRealmAccess().getRoles())
        || realm
            .getRolesStream()
            .anyMatch(role -> user.hasRole(role) && !ROLES.contains(role.getName()))
        || realm.getClientsStream().anyMatch(c -> c.getRolesStream().anyMatch(user::hasRole))
        || token.getResourceAccess().values().stream()
            .anyMatch(access -> access.getRoles() != null && !access.getRoles().isEmpty()))
      denied();
  }

  void requireTarget(KeycloakSession session, AuthResult auth, UserModel target) {
    var realm = session.getContext().getRealm();
    if (target == null
        || target.getServiceAccountClientLink() != null
        || target.getGroupsStream().anyMatch(group -> rootedAt(group, "protected-admins"))
        || target.getGroupsStream().noneMatch(group -> rootedAt(group, "human-roles"))
        || realm
            .getRolesStream()
            .anyMatch(role -> PROTECTED_ROLES.contains(role.getName()) && target.hasRole(role))
        || realm
            .getClientsStream()
            .filter(c -> "realm-management".equals(c.getClientId()))
            .anyMatch(c -> c.getRolesStream().anyMatch(target::hasRole))) denied();
    requireGroupsOnlyPermissions(session, auth);
    var client = realm.getClientByClientId(auth.getToken().getIssuedFor());
    var nativeRights =
        AdminPermissions.evaluator(
            session, realm, new AdminAuth(realm, auth.getToken(), auth.getUser(), client));
    if (nativeRights.isRealmAdmin()
        || nativeRights.realm().canManageRealm()
        || nativeRights.realm().canViewRealm()
        || nativeRights.users().canManage()
        || nativeRights.users().canView()
        || nativeRights.users().canQuery()
        || !nativeRights.users().canManage(target)) denied();
  }

  private static void requireGroupsOnlyPermissions(KeycloakSession session, AuthResult auth) {
    try {
      var realm = session.getContext().getRealm();
      var schema = AdminPermissionsSchema.SCHEMA;
      if (!schema.isAdminPermissionsEnabled(realm)) denied();
      var management = AdminPermissions.management(session, realm);
      var authorization = management.authz();
      var server = management.realmResourceServer();
      if (authorization == null || server == null) denied();
      var stores = authorization.getStoreFactory();
      var forbidden = new LinkedHashMap<String, ResourcePermission>();
      Set<String> represented = new HashSet<>();
      for (var type : schema.getResourceTypes().values()) {
        var resource = stores.getResourceStore().findByName(server, type.getType());
        if (resource == null
            || !resource.getScopes().stream()
                .map(scope -> scope.getName())
                .collect(Collectors.toSet())
                .equals(type.getScopes())) denied();
        forbidden.put(
            type.getType() + ":" + resource.getId(),
            new ResourcePermission(type.getType(), resource, resource.getScopes(), server));
        represented.add(resource.getId());
      }
      for (var policy : stores.getPolicyStore().findByResourceServer(server)) {
        if ("resource".equals(policy.getType())) denied();
        if (!"scope".equals(policy.getType())) {
          if (!policy.getScopes().isEmpty()) denied();
          continue;
        }
        var type = schema.getResourceTypes().get(policy.getResourceType());
        if (type == null
            || policy.getResources().isEmpty()
            || policy.getScopes().isEmpty()
            || !type.getScopes()
                .containsAll(
                    policy.getScopes().stream()
                        .map(scope -> scope.getName())
                        .collect(Collectors.toSet()))) denied();
        for (var resource : policy.getResources()) {
          if (!resource.getScopes().stream()
              .map(scope -> scope.getName())
              .collect(Collectors.toSet())
              .equals(type.getScopes())) denied();
          represented.add(resource.getId());
          var group =
              "Groups".equals(type.getType())
                  ? session.groups().getGroupById(realm, resource.getName())
                  : null;
          // Evaluate forbidden scopes with Keycloak itself. Only scoped ordinary
          // Groups member grants may authorize this actor; no local policy solver.
          var scopes =
              resource.getScopes().stream()
                  .filter(
                      scope ->
                          group == null
                              || !rootedAt(group, "human-roles")
                              || !Set.of(
                                      "view-members",
                                      "manage-members",
                                      "manage-membership-of-members")
                                  .contains(scope.getName()))
                  .collect(Collectors.toList());
          if (!scopes.isEmpty()) {
            forbidden.put(
                type.getType() + ":" + resource.getId(),
                new ResourcePermission(type.getType(), resource, scopes, server));
          }
        }
      }
      if (stores.getResourceStore().findByResourceServer(server).stream()
          .anyMatch(resource -> !represented.contains(resource.getId()))) denied();
      var context =
          new DefaultEvaluationContext(
              new KeycloakIdentity(auth.getToken(), session, realm), session);
      var decisions =
          authorization
              .evaluators()
              .from(forbidden.values(), server, context)
              .getDecision(server, null, DecisionPermissionCollector.class);
      if (!decisions.results().isEmpty()) denied();
    } catch (ForbiddenException failure) {
      throw failure;
    } catch (RuntimeException failure) {
      throw new ForbiddenException("C OTP native permission inventory is not verified");
    }
  }

  private static boolean rootedAt(GroupModel group, String name) {
    while (group.getParent() != null) group = group.getParent();
    return name.equals(group.getName());
  }

  private static void denied() {
    throw new ForbiddenException("C OTP operation is not authorized");
  }
}
