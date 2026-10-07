package org.oriso.keycloak.commands;

import static org.oriso.keycloak.commands.CommandValidation.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import java.util.*;
import org.keycloak.common.util.Time;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.*;
import org.keycloak.services.managers.AuthenticationManager;
import org.oriso.keycloak.auth.*;

/**
 * Durable UserService inactivity state supplies authority; this receiver supplies native effects.
 */
final class LifecycleCommands {
  private final KeycloakSession session;
  private final RealmModel realm;
  private final OriginAuthorization origins;

  LifecycleCommands(KeycloakSession session, OriginAuthorization origins) {
    this.session = session;
    this.realm = session.getContext().getRealm();
    this.origins = origins;
  }

  Response status(String id, String encoded) {
    var caller = TaskIdentity.require(session, "account-maintenance", "account-maintenance");
    var grant =
        origins.require(
            encoded,
            caller,
            "account.lifecycle-status",
            id,
            OriginAuthorization.JSON.createObjectNode(),
            false);
    var user = authorized(id, grant, true);
    Set<String> coarse = new TreeSet<>();
    if (user.getServiceAccountClientLink() != null) coarse.add("UNKNOWN");
    else {
      realm
          .getRolesStream()
          .filter(user::hasRole)
          .forEach(role -> classify(coarse, role.getName(), false));
      realm
          .getClientsStream()
          .forEach(
              client ->
                  client
                      .getRolesStream()
                      .filter(user::hasRole)
                      .forEach(
                          role ->
                              classify(
                                  coarse, role.getName(), "account".equals(client.getClientId()))));
    }
    // Human local consultant/admin records are corroborated by UserService before UNKNOWN fallback.
    return Response.ok(
            Map.of(
                "enabled", user.isEnabled(), "sessionCount", sessionCount(user), "roles", coarse))
        .header("Cache-Control", "no-store")
        .build();
  }

  Response access(String id, JsonNode body, String encoded, boolean restore) {
    fields(body, restore ? new String[] {"enabled"} : new String[] {});
    if (restore && !body.has("enabled")) bad();
    boolean enabled = restore && bool(body, "enabled", false);
    var caller = TaskIdentity.require(session, "account-maintenance", "account-maintenance");
    var grant =
        origins.require(
            encoded, caller, restore ? "account.restore" : "account.suspend", id, body, false);
    var user = authorized(id, grant, false);
    user.setEnabled(enabled);
    if (!restore) {
      // Same invalidation and backchannel logout as native UserResource.logout, without admin
      // grants.
      session.users().setNotBeforeForUser(realm, user, Time.currentTime());
      List<UserSessionModel> active;
      try (var sessions = session.sessions().getUserSessionsStream(realm, user)) {
        active = sessions.toList();
      }
      for (var activeSession : active)
        AuthenticationManager.backchannelLogout(
            session,
            realm,
            activeSession,
            session.getContext().getUri(),
            session.getContext().getConnection(),
            session.getContext().getRequestHeaders(),
            true);
    }
    if (user.isEnabled() != enabled || (!restore && sessionCount(user) != 0))
      throw new InternalServerErrorException("Native access change was not confirmed");
    CommandAudit.record(
        session,
        caller,
        OperationType.ACTION,
        "USER",
        "accounts/" + id,
        Map.of("accountId", id, "operation", restore ? "account.restore" : "account.suspend"));
    return Response.noContent().build();
  }

  private UserModel authorized(String id, OriginAuthorization.Grant grant, boolean readOnly) {
    if (!grant.originKind().equals("LIFECYCLE") || !grant.roles().isEmpty()) deny();
    var user = session.users().getUserById(realm, id);
    if (user == null) throw new NotFoundException("Account not found");
    if (readOnly) {
      if (!Objects.equals(user.getFirstAttribute("tenantId"), grant.tenantId())) deny();
    } else target(user, grant, realm);
    return user;
  }

  private long sessionCount(UserModel user) {
    try (var sessions = session.sessions().getUserSessionsStream(realm, user)) {
      return sessions.count();
    }
  }

  private static final Set<String> ACCOUNT_INFRASTRUCTURE =
      Set.of(
          "manage-account",
          "manage-account-links",
          "view-profile",
          "view-consent",
          "manage-consent",
          "view-applications",
          "delete-account");

  private void classify(Set<String> roles, String name, boolean account) {
    if (name != null
        && (name.equals("offline_access")
            || name.equals("uma_authorization")
            || name.startsWith("default-roles-")
            || (account && ACCOUNT_INFRASTRUCTURE.contains(name)))) return;
    if (name == null) roles.add("UNKNOWN");
    else if (Set.of("user", "anonymous").contains(name)) roles.add("ASKER");
    else if (name.equals("consultant")) roles.add("CONSULTANT");
    else roles.add("OTHER");
  }
}
