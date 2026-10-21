package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import static org.oriso.keycloak.lifecycle.NativeCurrentGrants.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.NotAuthorizedException;
import java.util.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AppAuthManager.BearerTokenAuthenticator;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.fgap.AdminPermissions;

/** Finite protected machine policy. Ordinary native authentication remains separate. */
final class ProtectedInvitationAuthorization {
  private static final Map<String, String> CLIENTS = Map.of(
      "SETUP", "backend-setup", "ACCOUNT_CREATE", "backend-account-create", "ACCOUNT_ADMIN", "backend-account-admin");
  private static final Map<String, Set<String>> ROLES = Map.of(
      "SETUP", Set.of("config-wizard", "invitation-reservations", "consultant-import"),
      "ACCOUNT_CREATE", Set.of("account-provisioning", "account-read"),
      "ACCOUNT_ADMIN", Set.of("account-maintenance", "account-read", "otp-config-admin", "session-exchange"));
  private final ProtectedInvitationConfiguration config;
  private final LifecycleAuthorization crypto;

  ProtectedInvitationAuthorization(ProtectedInvitationConfiguration config, LifecycleAuthorization crypto) {
    this.config = config; this.crypto = crypto;
  }

  LifecycleAuthorization.CheckedMachine requireMachine(KeycloakSession session, Set<String> allowedActors) {
    if (allowedActors.isEmpty() || !CLIENTS.keySet().containsAll(allowedActors)) deny();
    var auth = new BearerTokenAuthenticator(session).authenticate();
    if (auth == null) throw new NotAuthorizedException("Bearer");
    var token = auth.getToken();
    String actor = CLIENTS.entrySet().stream().filter(entry -> entry.getValue().equals(token.getIssuedFor()))
        .map(Map.Entry::getKey).findFirst().orElse(null);
    if (actor == null || !allowedActors.contains(actor) || auth.getClient() == null || auth.getUser() == null) deny();
    String clientId = CLIENTS.get(actor), subject = config.actors.get(actor);
    if (subject == null || !subject.equals(token.getSubject()) || !subject.equals(auth.getUser().getId())
        || !config.issuer.equals(token.getIssuer()) || token.getIat() == null) deny();
    var em = CurrentNativeHumanIdentity.entityManager(session);
    var realm = one(em, "select NAME, ENABLED, NOT_BEFORE from REALM where ID = :id for update", config.realmId);
    if (!config.realmId.equals(session.getContext().getRealm().getId()) || !config.realmName.equals(text(realm[0]))
        || !flag(realm[1]) || token.getIat() < ((Number) realm[2]).longValue()) deny();
    var client = one(em, "select REALM_ID, CLIENT_ID, ENABLED, PUBLIC_CLIENT, SERVICE_ACCOUNTS_ENABLED,"
        + " STANDARD_FLOW_ENABLED, DIRECT_ACCESS_GRANTS_ENABLED, FULL_SCOPE_ALLOWED, PROTOCOL, BEARER_ONLY,"
        + " IMPLICIT_FLOW_ENABLED, NOT_BEFORE, SECRET from CLIENT where ID = :id for update", auth.getClient().getId());
    if (!config.realmId.equals(text(client[0])) || !clientId.equals(text(client[1])) || !flag(client[2])
        || flag(client[3]) || !flag(client[4]) || flag(client[5]) || flag(client[6]) || flag(client[7])
        || !"openid-connect".equals(text(client[8])) || flag(client[9]) || flag(client[10])
        || token.getIat() < ((Number) client[11]).longValue()) deny();
    var matchingClients = em.createNativeQuery("select ID from CLIENT where REALM_ID = :realm and CLIENT_ID = :client for update")
        .setParameter("realm", config.realmId).setParameter("client", clientId).getResultList();
    if (matchingClients.size() != 1 || !auth.getClient().getId().equals(matchingClients.get(0).toString())) deny();
    var user = AccountLifecycleResource.lockedSnapshot(em, subject);
    if (!config.realmId.equals(user.path("realmId").asText()) || !user.path("enabled").asBoolean()
        || !user.path("federationLink").isNull() || !auth.getClient().getId().equals(user.path("serviceAccountClientLink").asText())) deny();
    var currentUser = one(em, "select ID, NOT_BEFORE from USER_ENTITY where ID = :id for update", subject);
    if (token.getIat() < ((Number) currentUser[1]).longValue()) deny();
    var serviceAccounts = em.createNativeQuery("select ID from USER_ENTITY where REALM_ID = :realm and SERVICE_ACCOUNT_CLIENT_LINK = :client for update")
        .setParameter("realm", config.realmId).setParameter("client", auth.getClient().getId()).getResultList();
    if (serviceAccounts.size() != 1 || !subject.equals(serviceAccounts.get(0).toString())) deny();
    var directRoles = jsonIds(user.path("roles"));
    var directGroups = jsonIds(user.path("groups"));
    if (directGroups.size() != 1) deny();
    var grants = read(em, config.realmId, directRoles, directGroups);
    String groupId = directGroups.iterator().next();
    var technical = grants.groups().get(groupId);
    var parent = technical == null ? null : grants.groups().get(technical.parentId());
    if (technical == null || parent == null || grants.groups().size() != 2
        || !"technical-identities".equals(technical.name()) || !"protected-admins".equals(parent.name())
        || parent.parentId() != null || !"/protected-admins/technical-identities".equals(grants.paths().get(groupId))) deny();
    for (String id : grants.groups().keySet())
      if (!ids(em, "select ROLE_ID from GROUP_ROLE_MAPPING where GROUP_ID = :id order by ROLE_ID for update", id).isEmpty()) deny();
    for (String id : directRoles) {
      var role = one(em, "select REALM_ID, CLIENT_ROLE, CLIENT from KEYCLOAK_ROLE where ID = :id for update", id);
      if (!config.realmId.equals(text(role[0])) || flag(role[1]) || role[2] != null
          || !ids(em, "select CHILD_ROLE from COMPOSITE_ROLE where COMPOSITE = :id order by CHILD_ROLE for update", id).isEmpty()) deny();
    }
    var expectedRoles = ROLES.get(actor);
    if (!expectedRoles.equals(grants.realmRoles()) || !grants.clientRoles().isEmpty()
        || token.getRealmAccess() == null || !expectedRoles.equals(token.getRealmAccess().getRoles())
        || token.getResourceAccess().values().stream().anyMatch(access -> access.getRoles() != null && !access.getRoles().isEmpty())) deny();
    var audiences = token.getAudience() == null ? Set.<String>of() : new HashSet<>(Arrays.asList(token.getAudience()));
    if (token.getAudience() == null || audiences.size() != token.getAudience().length
        || !HumanPolicyJson.strings(config.installation.path("machineAudienceSets").get(actor), 1, 30, 255).equals(audiences)) deny();
    var nativeRights = AdminPermissions.evaluator(session, session.getContext().getRealm(),
        new AdminAuth(session.getContext().getRealm(), token, auth.getUser(), auth.getClient()));
    if (nativeRights.isRealmAdmin() || nativeRights.realm().canManageRealm() || nativeRights.realm().canViewRealm()
        || nativeRights.users().canManage() || nativeRights.users().canView() || nativeRights.users().canQuery()) deny();
    LifecycleAuthorization.requireNoNativePermissions(session, token);
    crypto.requireDistinctNativeSecret(text(client[12]));
    return new LifecycleAuthorization.CheckedMachine(actor, clientId, subject, auth);
  }

  private static Set<String> jsonIds(JsonNode values) {
    var result = new TreeSet<String>();
    for (var value : values) if (!value.isTextual() || !result.add(value.asText())) deny();
    return Set.copyOf(result);
  }
}
