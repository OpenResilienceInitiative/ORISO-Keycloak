package org.oriso.keycloak.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.ForbiddenException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Short-lived authorization from the domain owner, bound to the entire command. */
public final class OriginAuthorization {
  public static final ObjectMapper JSON =
      new ObjectMapper()
          .enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
  public static final Set<String> HUMAN_ROLES =
      Set.of(
          "user",
          "consultant",
          "group-chat-consultant",
          "restricted-agency-admin",
          "user-admin",
          "agency-admin",
          "tenant-admin",
          "topic-admin");
  private static final Set<String> CLAIMS =
      Set.of(
          "iss",
          "aud",
          "iat",
          "exp",
          "jti",
          "purpose",
          "operation",
          "taskClient",
          "taskSubject",
          "originKind",
          "originAction",
          "target",
          "tenantId",
          "roles",
          "payloadDigest");
  private static final Set<String> KINDS =
      Set.of(
          "INVITATION",
          "REGISTRATION",
          "ANONYMOUS",
          "HUMAN_ADMIN",
          "SELF_SERVICE",
          "LIFECYCLE",
          "IMPORT",
          "ONBOARDING",
          "PASSWORD_RESET");
  private final byte[] provisioning;
  private final byte[] maintenance;

  public OriginAuthorization() {
    provisioning = key("ORISO_PROVISIONING_ORIGIN_KEY");
    maintenance = key("ORISO_MAINTENANCE_ORIGIN_KEY");
    if (MessageDigest.isEqual(provisioning, maintenance))
      throw new IllegalStateException("Origin keys must be distinct");
  }

  public record Grant(String originKind, String tenantId, Set<String> roles, String digest) {}

  public Grant require(
      String encoded,
      TaskIdentity.Caller caller,
      String operation,
      String target,
      JsonNode body,
      boolean creation) {
    try {
      if (encoded == null || encoded.length() > 8192) denied();
      String[] parts = encoded.split("\\.", -1);
      if (parts.length != 3) denied();
      JsonNode header = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
      if (!"HS256".equals(header.path("alg").asText())
          || !"JWT".equals(header.path("typ").asText())
          || header.size() != 2) denied();
      byte[] selected = creation ? provisioning : maintenance;
      if (!MessageDigest.isEqual(
          hmac(selected, parts[0] + "." + parts[1]), Base64.getUrlDecoder().decode(parts[2])))
        denied();
      JsonNode claim = JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));
      Set<String> names = new HashSet<>();
      claim.fieldNames().forEachRemaining(names::add);
      for (String name :
          Set.of(
              "iss",
              "aud",
              "jti",
              "purpose",
              "operation",
              "taskClient",
              "taskSubject",
              "originKind",
              "originAction",
              "target",
              "payloadDigest")) if (!claim.path(name).isTextual()) denied();
      if (!claim.path("iat").isIntegralNumber()
          || !claim.path("iat").canConvertToLong()
          || !claim.path("exp").isIntegralNumber()
          || !claim.path("exp").canConvertToLong()
          || (!claim.path("tenantId").isNull() && !claim.path("tenantId").isTextual())
          || claim.path("tenantId").asText().length() > 40) denied();
      long now = Instant.now().getEpochSecond(),
          iat = claim.path("iat").asLong(-1),
          exp = claim.path("exp").asLong(-1);
      if (!names.equals(CLAIMS)
          || !"oriso-userservice".equals(claim.path("iss").asText())
          || !TaskIdentity.AUDIENCE.equals(claim.path("aud").asText())
          || !"oriso-command".equals(claim.path("purpose").asText())
          || !operation.equals(claim.path("operation").asText())
          || !operation.equals(claim.path("originAction").asText())
          || !target.equals(claim.path("target").asText())
          || !caller.clientId().equals(claim.path("taskClient").asText())
          || !caller.subject().equals(claim.path("taskSubject").asText())
          || exp <= now
          || iat < now - 60
          || iat > now + 5
          || exp <= iat
          || exp - iat > 60
          || !KINDS.contains(claim.path("originKind").asText())
          || !claim.path("roles").isArray()
          || claim.path("roles").size() > 10) denied();
      if (!java.util
          .UUID
          .fromString(claim.path("jti").asText())
          .toString()
          .equals(claim.path("jti").asText())) denied();
      String kind = claim.path("originKind").asText();
      if ("SELF_SERVICE".equals(kind)
          && !Set.of("account.read", "account.profile", "account.password").contains(operation))
        denied();
      if ("IMPORT".equals(kind)) {
        Set<String> allowed =
            caller.clientId().equals(TaskIdentity.configured("account-provisioning"))
                ? Set.of("account.create", "account.commit", "account.compensate")
                : caller.clientId().equals(TaskIdentity.configured("account-maintenance"))
                    ? Set.of("account.read", "account.roles")
                    : Set.of();
        if (!allowed.contains(operation)) denied();
      }
      if (Set.of("ONBOARDING", "PASSWORD_RESET").contains(kind)
          && !Set.of("account.read", "account.password").contains(operation)) denied();
      String digest = encoded(hmac(selected, "payload\n" + canonical(body)));
      if (!MessageDigest.isEqual(
          digest.getBytes(StandardCharsets.UTF_8),
          claim.path("payloadDigest").asText().getBytes(StandardCharsets.UTF_8))) denied();
      Set<String> roles = new HashSet<>();
      for (JsonNode role : claim.get("roles")) {
        if (!role.isTextual() || !HUMAN_ROLES.contains(role.asText()) || !roles.add(role.asText()))
          denied();
      }
      if ("IMPORT".equals(claim.path("originKind").asText())
          && (!roles.contains("consultant")
              || !Set.of("consultant", "group-chat-consultant").containsAll(roles))) denied();
      String tenant = claim.path("tenantId").isNull() ? null : claim.path("tenantId").asText();
      return new Grant(claim.path("originKind").asText(), tenant, Set.copyOf(roles), digest);
    } catch (ForbiddenException e) {
      throw e;
    } catch (Exception e) {
      throw new ForbiddenException("Origin authorization is invalid");
    }
  }

  public String receipt(String realm, String attempt, String owner, String account) {
    return encoded(
        hmac(provisioning, "receipt\n" + realm + "\n" + attempt + "\n" + owner + "\n" + account));
  }

  public String fingerprint(JsonNode body) {
    return encoded(hmac(provisioning, "payload\n" + canonical(body)));
  }

  public static String canonical(JsonNode node) {
    try {
      return JSON.writeValueAsString(sorted(node));
    } catch (Exception e) {
      throw new IllegalArgumentException("Invalid command");
    }
  }

  private static Object sorted(JsonNode node) {
    if (node.isObject()) {
      TreeMap<String, Object> map = new TreeMap<>();
      node.fields().forEachRemaining(e -> map.put(e.getKey(), sorted(e.getValue())));
      return map;
    }
    if (node.isArray()) {
      java.util.List<Object> list = new java.util.ArrayList<>();
      node.forEach(n -> list.add(sorted(n)));
      return list;
    }
    if (node.isNull()) return null;
    if (node.isTextual()) return node.asText();
    if (node.isBoolean()) return node.asBoolean();
    if (node.isIntegralNumber()) return node.bigIntegerValue();
    throw new IllegalArgumentException("Floating command values unsupported");
  }

  private static byte[] key(String name) {
    try {
      String value = System.getenv(name);
      byte[] key = Base64.getDecoder().decode(value == null ? "" : value);
      if (key.length < 32) throw new IllegalStateException("Managed origin key missing: " + name);
      return key;
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException("Managed origin key invalid: " + name);
    }
  }

  private static byte[] hmac(byte[] key, String text) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return mac.doFinal(text.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new IllegalStateException("Authorization cryptography unavailable");
    }
  }

  private static String encoded(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static void denied() {
    throw new ForbiddenException("Origin authorization is invalid");
  }
}
