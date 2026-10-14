package org.oriso.keycloak.smtp;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.keycloak.authorization.common.DefaultEvaluationContext;
import org.keycloak.authorization.common.KeycloakIdentity;
import org.keycloak.authorization.fgap.AdminPermissionsSchema;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.DecisionPermissionCollector;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.fgap.AdminPermissions;

/** Bearer identity plus one short-lived, purpose-separated command proof. */
final class SmtpAuthorization {
  static final ObjectMapper JSON = new ObjectMapper()
      .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
  private static final Set<String> ROLES = Set.of(
      "smtp-sync", "system-email-delivery", "notification-dispatch", "notifications-technical");
  private static final Set<String> AUDIENCES = Set.of(
      "oriso-task-commands", "consultingtypeservice", "tenantservice", "userservice", "agencyservice");
  private static final Set<String> CLAIMS = Set.of(
      "iss", "aud", "purpose", "operation", "method", "actor", "realm", "target",
      "taskClient", "taskSubject", "payloadDigest", "jti", "nonce", "iat", "exp");
  private final String realmName;
  private final String subject;
  private final byte[] key;
  private final String encodedKey;

  SmtpAuthorization(String realmName, String subject, byte[] key, String encodedKey) {
    this.realmName = realmName;
    this.subject = subject;
    this.key = key.clone();
    this.encodedKey = encodedKey;
  }

  String require(KeycloakSession session, String proof, String operation, String method, JsonNode body) {
    var realm = session.getContext().getRealm();
    if (!realmName.equals(realm.getName())) denied();
    var auth = new BearerTokenAuthenticator(session).authenticate();
    if (auth == null) throw new NotAuthorizedException("Bearer");
    var token = auth.getToken();
    var client = realm.getClientByClientId("backend-mail");
    var user = auth.getUser();
    if (client == null || !client.isEnabled() || client.isPublicClient()
        || !client.isServiceAccountsEnabled() || client.isStandardFlowEnabled()
        || client.isDirectAccessGrantsEnabled() || client.isFullScopeAllowed()
        || !"backend-mail".equals(token.getIssuedFor())
        || !Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realmName).equals(token.getIssuer())
        || user == null || !user.isEnabled() || !subject.equals(user.getId())
        || !subject.equals(token.getSubject()) || !client.getId().equals(user.getServiceAccountClientLink())
        || token.getAudience() == null
        || !Arrays.asList(token.getAudience()).contains("oriso-task-commands")
        || !AUDIENCES.containsAll(Arrays.asList(token.getAudience()))) denied();
    var expected = session.users().getServiceAccount(client);
    if (expected == null || !subject.equals(expected.getId())
        || user.getGroupsStream().findAny().isPresent()) denied();
    var direct = user.getRoleMappingsStream().collect(Collectors.toList());
    if (direct.stream().anyMatch(role -> role.isClientRole() || role.isComposite())
        || !direct.stream().map(RoleModel::getName).collect(Collectors.toSet()).equals(ROLES)
        || token.getRealmAccess() == null || !ROLES.equals(token.getRealmAccess().getRoles())
        || realm.getRolesStream().anyMatch(role -> user.hasRole(role) && !ROLES.contains(role.getName()))
        || realm.getClientsStream().anyMatch(c -> c.getRolesStream().anyMatch(user::hasRole))
        || token.getResourceAccess().values().stream()
            .anyMatch(access -> access.getRoles() != null && !access.getRoles().isEmpty())) denied();
    // FGAP can grant native powers without adding a token role.
    var nativeRights = AdminPermissions.evaluator(session, realm, new AdminAuth(realm, token, user, client));
    if (nativeRights.isRealmAdmin() || nativeRights.realm().canManageRealm()
        || nativeRights.realm().canViewRealm() || nativeRights.users().canManage()
        || nativeRights.users().canView() || nativeRights.users().canQuery()) denied();
    requireNoNativePermissions(session, token);
    String secret = client.getSecret();
    if (secret == null || MessageDigest.isEqual(key, secret.getBytes(StandardCharsets.UTF_8))
        || MessageDigest.isEqual(encodedKey.getBytes(StandardCharsets.UTF_8),
                                 secret.getBytes(StandardCharsets.UTF_8))) denied();
    String digest = digest(body);
    verify(proof, operation, method, realm.getId(), digest);
    return digest;
  }

  private static void requireNoNativePermissions(
      KeycloakSession session, org.keycloak.representations.AccessToken token) {
    try {
      var realm = session.getContext().getRealm();
      var schema = AdminPermissionsSchema.SCHEMA;
      // This proposal supports the pinned v2 schema, never an uninspected v1 fallback.
      if (!schema.isAdminPermissionsEnabled(realm)) denied();
      var management = AdminPermissions.management(session, realm);
      var authorization = management.authz();
      var server = management.realmResourceServer();
      if (authorization == null || server == null) denied();
      var stores = authorization.getStoreFactory();
      var inventory = new LinkedHashMap<String, ResourcePermission>();
      Set<String> represented = new HashSet<>();
      // Global type resources exist even without permissions. Target resource types
      // come from the native scope policy, not Resource.getType() (which may be null).
      for (var type : schema.getResourceTypes().values()) {
        var resource = stores.getResourceStore().findByName(server, type.getType());
        if (resource == null || !resource.getScopes().stream().map(scope -> scope.getName())
            .collect(Collectors.toSet()).equals(type.getScopes())) denied();
        inventory.put(type.getType() + ":" + resource.getId(),
            new ResourcePermission(type.getType(), resource, resource.getScopes(), server));
        represented.add(resource.getId());
      }
      for (var policy : stores.getPolicyStore().findByResourceServer(server)) {
        if ("resource".equals(policy.getType())) denied();
        if (!"scope".equals(policy.getType())) {
          if (!policy.getScopes().isEmpty()) denied();
          continue; // Native condition policies are evaluated by Keycloak itself.
        }
        var type = schema.getResourceTypes().get(policy.getResourceType());
        if (type == null || policy.getResources().isEmpty() || policy.getScopes().isEmpty()
            || !type.getScopes().containsAll(policy.getScopes().stream()
                .map(scope -> scope.getName()).collect(Collectors.toSet()))) denied();
        for (var resource : policy.getResources()) {
          if (!resource.getScopes().stream().map(scope -> scope.getName())
              .collect(Collectors.toSet()).equals(type.getScopes())) denied();
          inventory.put(type.getType() + ":" + resource.getId(),
              new ResourcePermission(type.getType(), resource, resource.getScopes(), server));
          represented.add(resource.getId());
        }
      }
      if (stores.getResourceStore().findByResourceServer(server).stream()
          .anyMatch(resource -> !represented.contains(resource.getId()))) denied();
      // Same identity, context, typed permission and native DecisionPermissionCollector
      // path as Keycloak26.6.3 MgmtPermissions; no local policy/condition solver.
      var context = new DefaultEvaluationContext(new KeycloakIdentity(token, session, realm), session);
      var decisions = authorization.evaluators().from(inventory.values(), server, context)
          .getDecision(server, null, DecisionPermissionCollector.class);
      if (!decisions.results().isEmpty()) denied();
    } catch (ForbiddenException failure) {
      throw failure;
    } catch (RuntimeException failure) {
      throw new ForbiddenException("Native SMTP permission inventory is not verified");
    }
  }

  private void verify(String proof, String operation, String method, String target, String digest) {
    try {
      if (proof == null || proof.length() > 4096) denied();
      String[] parts = proof.split("\\.", -1);
      if (parts.length != 2 || !parts[0].matches("[A-Za-z0-9_-]+")
          || !parts[1].matches("[A-Za-z0-9_-]+")
          || !MessageDigest.isEqual(hmac("proof\n" + parts[0]), Base64.getUrlDecoder().decode(parts[1]))) denied();
      JsonNode claims = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
      Set<String> names = new HashSet<>();
      claims.fieldNames().forEachRemaining(names::add);
      if (!claims.isObject() || !names.equals(CLAIMS)) denied();
      for (String name : CLAIMS) {
        if (!Set.of("iat", "exp").contains(name) && !claims.path(name).isTextual()) denied();
      }
      if (!claims.path("iat").isIntegralNumber() || !claims.path("iat").canConvertToLong()
          || !claims.path("exp").isIntegralNumber() || !claims.path("exp").canConvertToLong()) denied();
      long now = Instant.now().getEpochSecond(), issued = claims.path("iat").asLong(), expires = claims.path("exp").asLong();
      if (!"oriso-smtp-sync".equals(claims.path("iss").asText())
          || !"oriso-smtp-control".equals(claims.path("aud").asText())
          || !"SMTP_SYNC".equals(claims.path("purpose").asText())
          || !operation.equals(claims.path("operation").asText())
          || !method.equals(claims.path("method").asText())
          || !"MAIL".equals(claims.path("actor").asText())
          || !realmName.equals(claims.path("realm").asText())
          || !target.equals(claims.path("target").asText())
          || !"backend-mail".equals(claims.path("taskClient").asText())
          || !subject.equals(claims.path("taskSubject").asText())
          || !MessageDigest.isEqual(digest.getBytes(StandardCharsets.UTF_8),
                                    claims.path("payloadDigest").asText().getBytes(StandardCharsets.UTF_8))
          || issued < now - 60 || issued > now + 5 || expires <= now
          || expires <= issued || expires - issued > 60
          || !UUID.fromString(claims.path("jti").asText()).toString().equals(claims.path("jti").asText())
          || !claims.path("nonce").asText().matches("[a-f0-9]{32}")) denied();
    } catch (ForbiddenException failure) {
      throw failure;
    } catch (Exception failure) {
      denied();
    }
  }

  private String digest(JsonNode body) {
    try {
      // The public schema is flat: scalars only. TreeMap makes ordering stable.
      var sorted = new TreeMap<String, JsonNode>();
      body.fields().forEachRemaining(field -> sorted.put(field.getKey(), field.getValue()));
      return HexFormat.of().formatHex(hmac("payload\n" + JSON.writeValueAsString(sorted)));
    } catch (Exception failure) {
      throw new ForbiddenException("Invalid SMTP command context");
    }
  }

  private byte[] hmac(String value) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
    } catch (Exception failure) {
      throw new IllegalStateException("SMTP context verification unavailable");
    }
  }

  private static void denied() { throw new ForbiddenException("SMTP control is not authorized"); }
}
