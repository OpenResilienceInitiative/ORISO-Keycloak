package org.oriso.keycloak.commands;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import java.util.*;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.oriso.keycloak.auth.OriginAuthorization.Grant;

final class CommandValidation {
  private CommandValidation() {}

  static final Set<String> HUMAN_ROLES = org.oriso.keycloak.auth.OriginAuthorization.HUMAN_ROLES;

  static void fields(JsonNode body, String... names) {
    if (body == null || !body.isObject() || body.toString().length() > 32768) bad();
    Set<String> allowed = Set.of(names);
    body.fieldNames()
        .forEachRemaining(
            n -> {
              if (!allowed.contains(n)) bad();
            });
  }

  static String text(JsonNode body, String name, boolean required, int max) {
    JsonNode value = body.get(name);
    if (value == null || value.isNull()) {
      if (required) bad();
      return null;
    }
    if (!value.isTextual()
        || value.asText().length() > max
        || (required && value.asText().isBlank())
        || value.asText().chars().anyMatch(c -> c < 32 || c == 127)) bad();
    return value.asText();
  }

  static String secret(JsonNode body, String name, boolean required) {
    JsonNode value = body.get(name);
    if (value == null || value.isNull()) {
      if (required) bad();
      return null;
    }
    if (!value.isTextual()
        || value.asText().length() > 4096
        || (required && value.asText().isEmpty())) bad();
    return value.asText();
  }

  static boolean bool(JsonNode body, String name, boolean fallback) {
    JsonNode v = body.get(name);
    if (v == null) return fallback;
    if (!v.isBoolean()) bad();
    return v.asBoolean();
  }

  static Set<String> roles(JsonNode body, Grant grant) {
    Set<String> result = roles(body);
    if (!grant.roles().containsAll(result)) deny();
    return result;
  }

  static Set<String> roles(JsonNode body) {
    JsonNode value = body.get("roles");
    if (value == null || !value.isArray() || value.size() > 10) bad();
    Set<String> result = new LinkedHashSet<>();
    for (JsonNode role : value) {
      if (!role.isTextual() || !HUMAN_ROLES.contains(role.asText())) deny();
      if (!result.add(role.asText())) bad();
    }
    return result;
  }

  static void target(UserModel user, Grant grant, RealmModel realm) {
    target(user, grant, realm, false);
  }

  static void target(UserModel user, Grant grant, RealmModel realm, boolean allowProtectedSelf) {
    if (user.getServiceAccountClientLink() != null) deny();
    if ("IMPORT".equals(grant.originKind())
        && user.getRealmRoleMappingsStream()
            .noneMatch(role -> role.getName().equals("consultant") && !role.isComposite())) deny();
    String tenant = user.getFirstAttribute("tenantId");
    if (!Objects.equals(tenant, grant.tenantId())) deny();
    if (!(allowProtectedSelf
            && Set.of("SELF_SERVICE", "PASSWORD_RESET").contains(grant.originKind()))
        && "0".equals(tenant)
        && realm.getRole("tenant-admin") != null
        && user.hasRole(realm.getRole("tenant-admin"))) deny();
  }

  static void createKind(String kind, Set<String> roles, Grant grant) {
    RegistrationPolicy policy = registrationPolicy(kind);
    Set<String> allowed = policy.allowedRoles();
    Set<String> required = policy.requiredRoles();
    if (!roles.containsAll(required) || !allowed.containsAll(roles)) deny();
    if (Set.of("AGENCY_ADMIN", "CONSULTANT_AGENCY_ADMIN", "TENANT_ADMIN").contains(kind)
        && !Set.of("INVITATION", "HUMAN_ADMIN").contains(grant.originKind())) deny();
    if (kind.equals("ANONYMOUS") && !grant.originKind().equals("ANONYMOUS")) deny();
    if ("IMPORT".equals(grant.originKind()) && !"CONSULTANT".equals(kind)) deny();
    if (!Set.of("REGISTRATION", "INVITATION", "ANONYMOUS", "HUMAN_ADMIN", "IMPORT")
        .contains(grant.originKind())) deny();
  }

  private record RegistrationPolicy(Set<String> requiredRoles, Set<String> allowedRoles) {}

  private static RegistrationPolicy registrationPolicy(String kind) {
    return switch (kind) {
      case "ASKER", "ANONYMOUS" -> new RegistrationPolicy(Set.of("user"), Set.of("user"));
      case "CONSULTANT" -> new RegistrationPolicy(
          Set.of("consultant"), Set.of("consultant", "group-chat-consultant"));
      case "AGENCY_ADMIN" -> new RegistrationPolicy(
          Set.of("restricted-agency-admin", "user-admin"),
          Set.of("restricted-agency-admin", "user-admin"));
      case "CONSULTANT_AGENCY_ADMIN" -> new RegistrationPolicy(
          Set.of("consultant", "restricted-agency-admin", "user-admin"),
          Set.of("consultant", "group-chat-consultant", "restricted-agency-admin", "user-admin"));
      case "TENANT_ADMIN" -> new RegistrationPolicy(
          Set.of("user-admin", "agency-admin", "tenant-admin"),
          Set.of("user-admin", "agency-admin", "tenant-admin", "topic-admin"));
      default -> throw new BadRequestException("Unsupported registration kind");
    };
  }

  static void bad() {
    throw new BadRequestException("Invalid bounded command");
  }

  static void deny() {
    throw new ForbiddenException("Origin is not authorized for this target or action");
  }
}
