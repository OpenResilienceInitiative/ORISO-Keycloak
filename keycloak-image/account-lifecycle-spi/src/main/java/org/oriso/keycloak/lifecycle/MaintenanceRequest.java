package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Set;

/** Strict finite command input; a decoded target is an assertion, never authorization. */
record MaintenanceRequest(
    String command,
    String accountId,
    JsonNode target,
    String operationId,
    String expectedState,
    JsonNode change,
    Long authorityValidUntil,
    String include) {
  static MaintenanceRequest parse(String command, String accountId, JsonNode body) {
    if (!Set.of("read", "profile", "email", "locale", "password", "self-password", "ordinary-profile",
        "deactivate", "reactivate", "delete").contains(command)) bad();
    boolean read = "read".equals(command);
    if (read && body.has("include")) fields(body, "target", "include");
    else if (read) fields(body, "target");
    else if ("self-password".equals(command) && body.has("authorityValidUntil"))
      fields(body, "target", "operationId", "expectedState", "change", "authorityValidUntil");
    else fields(body, "target", "operationId", "expectedState", "change");
    Long deadline = null;
    if (body.has("authorityValidUntil")) {
      var value = body.path("authorityValidUntil");
      if (!"self-password".equals(command) || !value.isIntegralNumber() || !value.canConvertToLong()
          || value.longValue() <= 0) bad();
      deadline = value.longValue();
    }
    var target = body.path("target");
    fields(target, "accountId", "tenantId", "origin");
    String actualId = text(target, "accountId", 255, false);
    if (!actualId.equals(accountId)) deny();
    String tenant = text(target, "tenantId", 20, true);
    if (tenant != null && !tenant.matches("0|[1-9][0-9]{0,18}")) bad();
    var origin = target.path("origin");
    fields(origin, "kind", "workflowId", "humanSubject", "humanIssuer", "humanClient", "humanAuthority");
    String kind = text(origin, "kind", 30, false);
    if (!Set.of("SELF", "HUMAN_ADMIN", "PASSWORD_RESET", "INVITATION", "IMPORT",
        "DELETION", "INACTIVITY", "REACTIVATION").contains(kind)) deny();
    text(origin, "workflowId", 512, false);
    String subject = text(origin, "humanSubject", 255, true);
    String issuer = text(origin, "humanIssuer", 512, true);
    String client = text(origin, "humanClient", 255, true);
    String authority = text(origin, "humanAuthority", 255, true);
    boolean human = Set.of("SELF", "HUMAN_ADMIN").contains(kind);
    if (human && (subject == null || issuer == null || client == null)
        || !human && (subject != null || issuer != null || client != null || authority != null)) deny();
    if ("SELF".equals(kind) && !actualId.equals(subject)
        || "HUMAN_ADMIN".equals(kind) && authority == null) deny();
    String include = null;
    if (read && body.has("include")) {
      include = text(body, "include", 40, false);
      if (!"TWO_FACTOR_STATUS_V1".equals(include) || !"HUMAN_ADMIN".equals(kind)
          || !"PROTECTED_ACCOUNT_OPERATIONS_V1".equals(authority)) bad();
    }
    if (read) return new MaintenanceRequest(command, accountId, target.deepCopy(), null, null, null, null, include);
    String operationId = text(body, "operationId", 36, false);
    uuid(operationId);
    String state = text(body, "expectedState", 64, false);
    hex(state);
    var change = body.path("change");
    switch (command) {
      case "profile" -> {
        fields(change, "firstName", "lastName", "email");
        text(change, "firstName", 255, true);
        text(change, "lastName", 255, true);
        text(change, "email", 255, true);
      }
      case "email" -> {
        fields(change, "email");
        text(change, "email", 255, false);
      }
      case "locale" -> {
        fields(change, "locale");
        text(change, "locale", 20, false);
      }
      case "password" -> {
        fields(change, "password", "temporary");
        text(change, "password", 4096, false);
        if (!change.path("temporary").isBoolean()) bad();
      }
      case "self-password" -> {
        fields(change, "currentPassword", "password", "temporary");
        text(change, "currentPassword", 4096, false);
        text(change, "password", 4096, false);
        if (!change.path("temporary").isBoolean() || change.path("temporary").asBoolean()) bad();
        if (change.path("currentPassword").equals(change.path("password")))
          throw new jakarta.ws.rs.ClientErrorException("The new password must differ", 409);
      }
      case "ordinary-profile" -> {
        if (change.has("profile")) {
          fields(change, "group", "profile");
          fields(change.path("profile"), "firstName", "lastName", "email");
          text(change.path("profile"), "firstName", 255, true);
          text(change.path("profile"), "lastName", 255, true);
          text(change.path("profile"), "email", 255, true);
        } else fields(change, "group");
        String group = text(change, "group", 512, false);
        if (!group.matches("/human-roles/[a-z0-9-]{1,80}")) deny();
      }
      case "reactivate" -> {
        fields(change, "expectedUsername", "expectedEmail", "password");
        text(change, "expectedUsername", 255, false);
        text(change, "expectedEmail", 255, false);
        text(change, "password", 4096, false);
      }
      case "deactivate", "delete" -> fields(change);
      default -> bad();
    }
    return new MaintenanceRequest(command, accountId, target.deepCopy(), operationId, state, change.deepCopy(), deadline, null);
  }

  void requireEffectDeadline() {
    if (authorityValidUntil != null && authorityValidUntil <= java.time.Instant.now().getEpochSecond())
      throw new jakarta.ws.rs.BadRequestException("Password intent expired");
  }

  static JsonNode availability(JsonNode body) {
    fields(body, "selector", "value");
    String selector = text(body, "selector", 8, false);
    if (!Set.of("username", "email").contains(selector)) bad();
    text(body, "value", 255, false);
    return body.deepCopy();
  }

  @Override
  public String toString() {
    return "MaintenanceRequest[command=" + command + ", payload=redacted]";
  }
}
