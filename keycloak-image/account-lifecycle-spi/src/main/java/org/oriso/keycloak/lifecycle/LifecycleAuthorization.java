package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.keycloak.authorization.common.*;
import org.keycloak.authorization.fgap.AdminPermissionsSchema;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.DecisionPermissionCollector;
import org.keycloak.models.*;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.fgap.AdminPermissions;

final class LifecycleAuthorization {
  private static final Set<String> CLAIMS =
      Set.of(
          "iss",
          "aud",
          "purpose",
          "operation",
          "method",
          "actor",
          "realm",
          "target",
          "taskClient",
          "taskSubject",
          "payloadDigest",
          "jti",
          "nonce",
          "iat",
          "exp");
  final String realmName, creatorSubject, adminSubject;
  private final byte[] key;
  private final String encodedKey;

  LifecycleAuthorization(
      String realm, String creator, String admin, byte[] key, String encodedKey) {
    this.realmName = realm;
    this.creatorSubject = creator;
    this.adminSubject = admin;
    this.key = key.clone();
    this.encodedKey = encodedKey;
  }

  String require(
      KeycloakSession session,
      String proof,
      String operation,
      String method,
      String attempt,
      JsonNode body) {
    var realm = session.getContext().getRealm();
    var machine = authenticateMachine(session);
    String actor = machine.actor();
    if ("ACCOUNT_ADMIN".equals(actor)
        && !Set.of("account.creation-recover", "account.compensate").contains(operation)) deny();
    verifyCommand(
        proof,
        machine,
        "oriso-account-lifecycle",
        "ACCOUNT_CREATE".equals(actor) ? "ACCOUNT_PROVISIONING" : "ACCOUNT_MAINTENANCE",
        operation,
        method,
        "realm/" + realm.getId() + "/account-attempt/" + attempt,
        body);
    return actor;
  }

  /** Cached native machine identity; subsequent human authentication must not replace it. */
  record CheckedMachine(
      String actor, String clientId, String subject,
      org.keycloak.services.managers.AuthenticationManager.AuthResult nativeAuth) {}

  CheckedMachine requireMachine(KeycloakSession session, String requiredActor) {
    if (!Set.of("ACCOUNT_CREATE", "ACCOUNT_ADMIN").contains(requiredActor)) deny();
    var checked = authenticateMachine(session);
    if (!requiredActor.equals(checked.actor())) deny();
    return checked;
  }

  private CheckedMachine authenticateMachine(KeycloakSession session) {
    var realm = session.getContext().getRealm();
    var auth = new BearerTokenAuthenticator(session).authenticate();
    if (auth == null) throw new NotAuthorizedException("Bearer");
    var token = auth.getToken();
    var user = auth.getUser();
    String actor =
        "backend-account-create".equals(token.getIssuedFor()) ? "ACCOUNT_CREATE" : "ACCOUNT_ADMIN";
    String clientId =
        "ACCOUNT_CREATE".equals(actor) ? "backend-account-create" : "backend-account-admin";
    String subject = "ACCOUNT_CREATE".equals(actor) ? creatorSubject : adminSubject;
    var roles =
        "ACCOUNT_CREATE".equals(actor)
            ? Set.of("account-provisioning", "account-read")
            : Set.of("account-maintenance", "account-read", "otp-config-admin", "session-exchange");
    var audiences =
        "ACCOUNT_CREATE".equals(actor)
            ? Set.of("userservice", "oriso-account-lifecycle")
            : Set.of("userservice", "oriso-account-lifecycle", "oriso-otp");
    var client = realm.getClientByClientId(clientId);
    if (!realmName.equals(realm.getName())
        || client == null
        || !client.isEnabled()
        || client.isPublicClient()
        || !client.isServiceAccountsEnabled()
        || client.isStandardFlowEnabled()
        || client.isDirectAccessGrantsEnabled()
        || client.isFullScopeAllowed()
        || !clientId.equals(token.getIssuedFor())
        || user == null
        || !user.isEnabled()
        || !subject.equals(user.getId())
        || !subject.equals(token.getSubject())
        || !client.getId().equals(user.getServiceAccountClientLink())
        || !Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realmName)
            .equals(token.getIssuer())
        || token.getAudience() == null
        || !audiences.equals(new HashSet<>(Arrays.asList(token.getAudience())))) deny();
    var expected = session.users().getServiceAccount(client);
    if (expected == null || !subject.equals(expected.getId())) deny();
    var memberships = user.getGroupsStream().limit(2).toList();
    if (memberships.size() != 1) deny();
    var technical = memberships.get(0);
    var parent = technical.getParent();
    if (!"technical-identities".equals(technical.getName())
        || parent == null
        || !"protected-admins".equals(parent.getName())
        || parent.getParent() != null
        || technical.getRoleMappingsStream().findAny().isPresent()
        || parent.getRoleMappingsStream().findAny().isPresent()) deny();
    var direct = user.getRoleMappingsStream().toList();
    if (direct.stream().anyMatch(r -> r.isClientRole() || r.isComposite())
        || !direct.stream().map(RoleModel::getName).collect(Collectors.toSet()).equals(roles)
        || token.getRealmAccess() == null
        || !roles.equals(token.getRealmAccess().getRoles())
        || realm.getRolesStream().anyMatch(r -> user.hasRole(r) && !roles.contains(r.getName()))
        || realm.getClientsStream().anyMatch(c -> c.getRolesStream().anyMatch(user::hasRole))
        || token.getResourceAccess().values().stream()
            .anyMatch(a -> a.getRoles() != null && !a.getRoles().isEmpty())) deny();
    var nativeRights =
        AdminPermissions.evaluator(session, realm, new AdminAuth(realm, token, user, client));
    if (nativeRights.isRealmAdmin()
        || nativeRights.realm().canManageRealm()
        || nativeRights.realm().canViewRealm()
        || nativeRights.users().canManage()
        || nativeRights.users().canView()
        || nativeRights.users().canQuery()) deny();
    requireNoNativePermissions(session, token);
    String secret = client.getSecret();
    if (secret == null
        || MessageDigest.isEqual(key, secret.getBytes(StandardCharsets.UTF_8))
        || MessageDigest.isEqual(
            encodedKey.getBytes(StandardCharsets.UTF_8), secret.getBytes(StandardCharsets.UTF_8)))
      deny();
    return new CheckedMachine(actor, clientId, subject, auth);
  }

  void verifyCommand(
      String proof,
      CheckedMachine machine,
      String proofAudience,
      String purpose,
      String operation,
      String method,
      String target,
      JsonNode body) {
    String actor = machine.actor(), client = machine.clientId(), subject = machine.subject();
    try {
      if (proof == null || proof.length() > 8192) deny();
      String[] parts = proof.split("\\.", -1);
      if (parts.length != 2
          || !parts[0].matches("[A-Za-z0-9_-]+")
          || !parts[1].matches("[A-Za-z0-9_-]+")
          || !MessageDigest.isEqual(
              bytes("proof\n" + parts[0]), Base64.getUrlDecoder().decode(parts[1]))) deny();
      var claims = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
      fields(claims, CLAIMS.toArray(String[]::new));
      for (var name : CLAIMS)
        if (!Set.of("iat", "exp").contains(name) && !claims.path(name).isTextual()) deny();
      if (!claims.path("iat").isIntegralNumber()
          || !claims.path("iat").canConvertToLong()
          || !claims.path("exp").isIntegralNumber()
          || !claims.path("exp").canConvertToLong()) deny();
      long now = Instant.now().getEpochSecond(),
          issued = claims.path("iat").asLong(),
          expires = claims.path("exp").asLong();
      if (!"userservice".equals(claims.path("iss").asText())
          || !proofAudience.equals(claims.path("aud").asText())
          || !purpose.equals(claims.path("purpose").asText())
          || !operation.equals(claims.path("operation").asText())
          || !method.equals(claims.path("method").asText())
          || !actor.equals(claims.path("actor").asText())
          || !realmName.equals(claims.path("realm").asText())
          || !target.equals(claims.path("target").asText())
          || !client.equals(claims.path("taskClient").asText())
          || !subject.equals(claims.path("taskSubject").asText())
          || !equal(mac("payload", body), claims.path("payloadDigest").asText())
          || issued < now - 60
          || issued > now + 5
          || expires <= now
          || expires <= issued
          || expires - issued > 60
          || !UUID.fromString(claims.path("jti").asText())
              .toString()
              .equals(claims.path("jti").asText())
          || !claims.path("nonce").asText().matches("[a-f0-9]{32}")) deny();
    } catch (ForbiddenException failure) {
      throw failure;
    } catch (Exception failure) {
      deny();
    }
  }

  String mac(String domain, JsonNode value) {
    return HexFormat.of().formatHex(bytes(domain + "\n" + canonical(value)));
  }

  String creationReceipt(JsonNode value) {
    String encoded =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(canonical(value).getBytes(StandardCharsets.UTF_8));
    return encoded
        + "."
        + Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(bytes("creation-proof\n" + encoded));
  }

  String receipt(String domain, JsonNode value) {
    String encoded =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(canonical(value).getBytes(StandardCharsets.UTF_8));
    return encoded + "." + HexFormat.of().formatHex(bytes(domain + "\n" + encoded));
  }

  static boolean equal(String left, String right) {
    return left != null
        && right != null
        && MessageDigest.isEqual(
            left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));
  }

  private byte[] bytes(String value) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
    } catch (Exception failure) {
      throw new IllegalStateException("Lifecycle context verification unavailable");
    }
  }

  static void requireNoNativePermissions(
      KeycloakSession session, org.keycloak.representations.AccessToken token) {
    try {
      var realm = session.getContext().getRealm();
      var schema = AdminPermissionsSchema.SCHEMA;
      // This proposal supports the pinned v2 schema, never an uninspected v1 fallback.
      if (!schema.isAdminPermissionsEnabled(realm)) deny();
      var management = AdminPermissions.management(session, realm);
      var authorization = management.authz();
      var server = management.realmResourceServer();
      if (authorization == null || server == null) deny();
      var stores = authorization.getStoreFactory();
      var inventory = new LinkedHashMap<String, ResourcePermission>();
      Set<String> represented = new HashSet<>();
      // Global type resources exist even without permissions. Target resource types
      // come from the native scope policy, not Resource.getType() (which may be null).
      for (var type : schema.getResourceTypes().values()) {
        var resource = stores.getResourceStore().findByName(server, type.getType());
        if (resource == null
            || !resource.getScopes().stream()
                .map(scope -> scope.getName())
                .collect(Collectors.toSet())
                .equals(type.getScopes())) deny();
        inventory.put(
            type.getType() + ":" + resource.getId(),
            new ResourcePermission(type.getType(), resource, resource.getScopes(), server));
        represented.add(resource.getId());
      }
      for (var policy : stores.getPolicyStore().findByResourceServer(server)) {
        if ("resource".equals(policy.getType())) deny();
        if (!"scope".equals(policy.getType())) {
          if (!policy.getScopes().isEmpty()) deny();
          continue; // Native condition policies are evaluated by Keycloak itself.
        }
        var type = schema.getResourceTypes().get(policy.getResourceType());
        if (type == null
            || policy.getResources().isEmpty()
            || policy.getScopes().isEmpty()
            || !type.getScopes()
                .containsAll(
                    policy.getScopes().stream()
                        .map(scope -> scope.getName())
                        .collect(Collectors.toSet()))) deny();
        for (var resource : policy.getResources()) {
          if (!resource.getScopes().stream()
              .map(scope -> scope.getName())
              .collect(Collectors.toSet())
              .equals(type.getScopes())) deny();
          inventory.put(
              type.getType() + ":" + resource.getId(),
              new ResourcePermission(type.getType(), resource, resource.getScopes(), server));
          represented.add(resource.getId());
        }
      }
      if (stores.getResourceStore().findByResourceServer(server).stream()
          .anyMatch(resource -> !represented.contains(resource.getId()))) deny();
      // Same identity, context, typed permission and native DecisionPermissionCollector
      // path as Keycloak26.6.3 MgmtPermissions; no local policy/condition solver.
      var context =
          new DefaultEvaluationContext(new KeycloakIdentity(token, session, realm), session);
      var decisions =
          authorization
              .evaluators()
              .from(inventory.values(), server, context)
              .getDecision(server, null, DecisionPermissionCollector.class);
      if (!decisions.results().isEmpty()) deny();
    } catch (ForbiddenException failure) {
      throw failure;
    } catch (RuntimeException failure) {
      throw new ForbiddenException("Native lifecycle permission inventory is not verified");
    }
  }
}
