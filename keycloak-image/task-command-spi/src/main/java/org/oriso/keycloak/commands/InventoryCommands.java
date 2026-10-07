package org.oriso.keycloak.commands;

import static org.oriso.keycloak.commands.CommandValidation.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;
import org.keycloak.models.*;
import org.oriso.keycloak.auth.OriginAuthorization;
import org.oriso.keycloak.auth.TaskIdentity;

/** Read-only orphan inventory authorized by the locked, persisted inactivity rollout. */
final class InventoryCommands {
  private static final Set<String> MACHINE_ROLES =
      Set.of(
          "technical",
          "otp-config-admin",
          "config-wizard",
          "invitation-reservations",
          "notification-dispatch",
          "notifications-technical",
          "system-email-delivery",
          "runtime-policy",
          "matrix-agency",
          "matrix-agency-provision",
          "appointment-sync",
          "appointment-participant-cleanup",
          "account-provisioning",
          "account-maintenance",
          "account-read",
          "session-exchange",
          "smtp-sync",
          "consultant-import");
  private final KeycloakSession session;
  private final OriginAuthorization origins;

  InventoryCommands(KeycloakSession session, OriginAuthorization origins) {
    this.session = session;
    this.origins = origins;
  }

  Response read(JsonNode body, String encoded) {
    var caller = TaskIdentity.require(session, "account-maintenance", "account-maintenance");
    fields(body, "cutoff", "first", "max");
    String cutoff = text(body, "cutoff", true, 40);
    try {
      Instant.parse(cutoff);
    } catch (java.time.format.DateTimeParseException e) {
      bad();
    }
    int first = integer(body, "first", 0, Integer.MAX_VALUE), max = integer(body, "max", 1, 1000);
    var grant =
        origins.require(
            encoded,
            caller,
            "account.inventory",
            "cutoff:" + cutoff + "/first:" + first + "/max:" + max,
            body,
            false);
    if (!grant.originKind().equals("LIFECYCLE")
        || grant.tenantId() != null
        || !grant.roles().isEmpty()) deny();
    RealmModel realm = session.getContext().getRealm();
    List<UserModel> page;
    try (Stream<UserModel> users =
        session
            .users()
            .searchForUserStream(
                realm, Map.of(UserModel.INCLUDE_SERVICE_ACCOUNT, "true"), first, max)) {
      page = users.toList();
    }
    List<Map<String, Object>> accounts = new ArrayList<>();
    for (UserModel user : page) {
      Map<String, Object> item = new LinkedHashMap<>();
      item.put("id", user.getId());
      item.put("tenantId", nullable(user.getFirstAttribute("tenantId")));
      item.put("createdTimestamp", nullable(user.getCreatedTimestamp()));
      item.put("eligibleHuman", eligible(realm, user));
      accounts.add(item);
    }
    return Response.ok(Map.of("accounts", accounts, "hasMore", page.size() == max))
        .header("Cache-Control", "no-store")
        .build();
  }

  private boolean eligible(RealmModel realm, UserModel user) {
    if (user.getServiceAccountClientLink() != null) return false;
    Set<String> effective = new HashSet<>();
    realm
        .getRolesStream()
        .filter(role -> !role.isComposite() && user.hasRole(role))
        .forEach(role -> effective.add(role.getName()));
    realm
        .getClientsStream()
        .forEach(
            client ->
                client
                    .getRolesStream()
                    .filter(role -> !role.isComposite() && user.hasRole(role))
                    .forEach(role -> effective.add(role.getName())));
    boolean technical = effective.stream().anyMatch(MACHINE_ROLES::contains);
    boolean human =
        effective.stream()
            .anyMatch(
                name ->
                    name == null
                        || !(MACHINE_ROLES.contains(name)
                            || name.startsWith("default-roles-")
                            || Set.of(
                                    "offline_access",
                                    "uma_authorization",
                                    "manage-account",
                                    "manage-account-links",
                                    "view-profile",
                                    "view-consent",
                                    "manage-consent",
                                    "view-applications",
                                    "delete-account")
                                .contains(name)));
    return human || !technical;
  }

  private Object nullable(Object value) {
    return value == null ? com.fasterxml.jackson.databind.node.NullNode.instance : value;
  }

  private int integer(JsonNode body, String field, int min, int max) {
    JsonNode value = body.get(field);
    if (value == null
        || !value.isIntegralNumber()
        || !value.canConvertToInt()
        || value.asInt() < min
        || value.asInt() > max) bad();
    return value.asInt();
  }
}
