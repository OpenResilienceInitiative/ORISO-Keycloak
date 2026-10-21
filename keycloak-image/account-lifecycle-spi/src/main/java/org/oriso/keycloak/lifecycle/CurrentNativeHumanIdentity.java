package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.EntityManager;
import java.util.*;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.fgap.AdminPermissions;
import org.keycloak.urls.HostnameProvider;
import org.keycloak.urls.UrlType;

/** Natively authenticated, current local human identity. Carries no operation authority. */
public final class CurrentNativeHumanIdentity {
  public static NativePolicy nativePolicy(JsonNode config) {
    fields(config, "realmId", "issuer", "clientIds", "audienceSets", "technicalSubjects", "technicalGroupIds", "technicalRoles");
    return new NativePolicy(config);
  }

  public static final class NativePolicy {
    final String realmId, issuer;
    final Set<String> clients, subjects, groups, technicalRoles;
    final Set<Set<String>> audiences;
    private NativePolicy(JsonNode config) {
      realmId = text(config, "realmId", 255, false);
      issuer = text(config, "issuer", 512, false);
      clients = HumanPolicyJson.strings(config.get("clientIds"), 1, 30, 255);
      audiences = HumanPolicyJson.audiences(config.get("audienceSets"));
      subjects = HumanPolicyJson.strings(config.get("technicalSubjects"), 5, 1000, 36);
      subjects.forEach(LifecycleJson::uuid);
      groups = HumanPolicyJson.strings(config.get("technicalGroupIds"), 1, 100, 255);
      technicalRoles = HumanPolicyJson.strings(config.get("technicalRoles"), 1, 200, 255);
      if (!technicalRoles.containsAll(Set.of("config-wizard", "invitation-reservations", "consultant-import",
          "account-provisioning", "account-read", "account-maintenance", "otp-config-admin", "session-exchange",
          "smtp-sync", "system-email-delivery", "notification-dispatch", "notifications-technical",
          "runtime-policy", "matrix-agency", "matrix-agency-provision", "appointment-sync", "appointment-participant-cleanup"))) bad();
    }
  }

  public static void validateInstallation(KeycloakSession session, NativePolicy policy) {
    var realm = session.getContext().getRealm();
    if (realm == null || !policy.realmId.equals(realm.getId())
        || !policy.issuer.equals(installedIssuer(session))) deny();
    var em = entityManager(session);
    for (String clientId : policy.clients) {
      var rows = em.createNativeQuery("select ID from CLIENT where REALM_ID = :realm and CLIENT_ID = :client for update")
          .setParameter("realm", policy.realmId).setParameter("client", clientId).getResultList();
      if (rows.size() != 1) deny();
      currentClient(em, policy.realmId, rows.get(0).toString(), clientId, null);
    }
    for (String subject : policy.subjects) {
      var rows = em.createNativeQuery("select ID from USER_ENTITY where REALM_ID = :realm and ID = :id for update")
          .setParameter("realm", policy.realmId).setParameter("id", subject).getResultList();
      if (rows.size() != 1) deny();
    }
    for (var subject : em.createNativeQuery("select ID from USER_ENTITY where REALM_ID = :realm and SERVICE_ACCOUNT_CLIENT_LINK is not null for update")
        .setParameter("realm", policy.realmId).getResultList()) if (!policy.subjects.contains(subject.toString())) deny();
    NativeCurrentGrants.read(em, policy.realmId, Set.of(), policy.groups);
    for (String role : policy.technicalRoles) {
      var rows = em.createNativeQuery("select ID from KEYCLOAK_ROLE where REALM_ID = :realm and NAME = :name and CLIENT_ROLE = false for update")
          .setParameter("realm", policy.realmId).setParameter("name", role).getResultList();
      if (rows.size() != 1) deny();
    }
  }

  public static VerifiedHuman require(KeycloakSession session, NativePolicy policy) {
    return verify(session, policy, NativeHumanBearer.require(session));
  }

  public static VerifiedHuman require(KeycloakSession session, NativePolicy policy, String rawBearer) {
    return verify(session, policy, NativeHumanBearer.require(session, rawBearer));
  }

  private static VerifiedHuman verify(KeycloakSession session, NativePolicy policy,
      org.keycloak.services.managers.AuthenticationManager.AuthResult auth) {
    var realm = session.getContext().getRealm();
    var token = auth.getToken();
    var em = entityManager(session);
    var currentRealm = NativeCurrentGrants.one(em, "select NAME, ENABLED, NOT_BEFORE from REALM where ID = :id for update", policy.realmId);
    if (!realm.getName().equals(NativeCurrentGrants.text(currentRealm[0])) || !NativeCurrentGrants.flag(currentRealm[1])
        || token.getIat() == null || token.getIat() < ((Number) currentRealm[2]).longValue()) deny();
    if (!policy.realmId.equals(realm.getId()) || !policy.issuer.equals(token.getIssuer())
        || !policy.clients.contains(token.getIssuedFor()) || policy.subjects.contains(token.getSubject())) deny();
    uuid(token.getSubject());
    currentClient(em, policy.realmId, auth.getClient().getId(), token.getIssuedFor(), token.getIat());
    var user = AccountLifecycleResource.lockedSnapshot(em, token.getSubject());
    if (!policy.realmId.equals(user.path("realmId").asText()) || !user.path("enabled").asBoolean()
        || !user.path("serviceAccountClientLink").isNull() || !user.path("federationLink").isNull()) deny();
    var directGroups = jsonIds(user.path("groups"));
    var grants = NativeCurrentGrants.read(em, policy.realmId, jsonIds(user.path("roles")), directGroups);
    if (!Collections.disjoint(grants.groups().keySet(), policy.groups)
        || !Collections.disjoint(grants.realmRoles(), policy.technicalRoles)) deny();
    var realmRoles = token.getRealmAccess() == null || token.getRealmAccess().getRoles() == null
        ? Set.<String>of() : Set.copyOf(token.getRealmAccess().getRoles());
    var clientRoles = new TreeMap<String, Set<String>>();
    token.getResourceAccess().forEach((client, access) -> {
      if (access.getRoles() != null && !access.getRoles().isEmpty()) clientRoles.put(client, Set.copyOf(access.getRoles()));
    });
    if (!realmRoles.equals(grants.realmRoles()) || !clientRoles.equals(grants.clientRoles())) deny();
    var audiences = token.getAudience() == null ? Set.<String>of() : new HashSet<>(Arrays.asList(token.getAudience()));
    if (token.getAudience() == null || audiences.size() != token.getAudience().length || !policy.audiences.contains(audiences)) deny();
    Long tenant = tenant(user.path("attributes").get("tenantId"), token.getOtherClaims().get("tenantId"));
    var permissions = AdminPermissions.evaluator(session, realm, new AdminAuth(realm, token, auth.getUser(), auth.getClient()));
    if (permissions.isRealmAdmin() || permissions.realm().canManageRealm() || permissions.realm().canViewRealm()
        || permissions.users().canManage() || permissions.users().canView() || permissions.users().canQuery()) deny();
    LifecycleAuthorization.requireNoNativePermissions(session, token);
    var groups = new TreeMap<String, CurrentGroup>();
    grants.groups().forEach((id, group) -> groups.put(id, new CurrentGroup(id, grants.paths().get(id), group.parentId())));
    return new VerifiedHuman(policy.realmId, realm.getName(), token.getSubject(), token.getIssuer(),
        token.getIssuedFor(), auth.getClient().getId(), auth.getSession().getId(), tenant, Set.copyOf(audiences),
        directGroups, Map.copyOf(groups), grants.realmRoles(), grants.clientRoles());
  }

  static void currentClient(EntityManager em, String realmId, String uuid, String clientId, Long issuedAt) {
    var row = NativeCurrentGrants.one(em,
        "select REALM_ID, CLIENT_ID, ENABLED, STANDARD_FLOW_ENABLED, SERVICE_ACCOUNTS_ENABLED, PROTOCOL, BEARER_ONLY, NOT_BEFORE from CLIENT where ID = :id for update", uuid);
    if (!realmId.equals(NativeCurrentGrants.text(row[0])) || !clientId.equals(NativeCurrentGrants.text(row[1]))
        || !NativeCurrentGrants.flag(row[2]) || !NativeCurrentGrants.flag(row[3]) || NativeCurrentGrants.flag(row[4])
        || !"openid-connect".equals(NativeCurrentGrants.text(row[5])) || NativeCurrentGrants.flag(row[6])
        || issuedAt != null && issuedAt < ((Number) row[7]).longValue()) deny();
  }

  static String installedIssuer(KeycloakSession session) {
    // Startup has no incoming request. A reviewed full native hostname/frontendUrl
    // must resolve independently; request-selected hostnames cannot establish this binding.
    var nativeHostname = session.getProvider(HostnameProvider.class);
    var base = jakarta.ws.rs.core.UriBuilder.fromPath(nativeHostname.getContextPath(null, UrlType.FRONTEND))
        .scheme(nativeHostname.getScheme(null, UrlType.FRONTEND))
        .host(nativeHostname.getHostname(null, UrlType.FRONTEND))
        .port(nativeHostname.getPort(null, UrlType.FRONTEND)).build();
    return Urls.realmIssuer(base, session.getContext().getRealm().getName());
  }

  private static Long tenant(JsonNode nativeValues, Object claim) {
    if (nativeValues == null && claim == null) return null;
    if (nativeValues == null || !nativeValues.isArray() || nativeValues.size() != 1
        || !nativeValues.get(0).isTextual() || !(claim instanceof String)
        || !nativeValues.get(0).asText().equals(claim)
        || !((String) claim).matches("0|[1-9][0-9]{0,18}")) deny();
    try { return Long.valueOf((String) claim); }
    catch (NumberFormatException failure) { deny(); return null; }
  }

  private static Set<String> jsonIds(JsonNode values) {
    var result = new TreeSet<String>();
    for (var value : values) if (!value.isTextual() || !result.add(value.asText())) deny();
    return Set.copyOf(result);
  }

  static EntityManager entityManager(KeycloakSession session) {
    return session.getProvider(JpaConnectionProvider.class).getEntityManager();
  }

  public static final class CurrentGroup {
    private final String id, path, parentId;
    private CurrentGroup(String id, String path, String parentId) { this.id = id; this.path = path; this.parentId = parentId; }
    public String id() { return id; }
    public String path() { return path; }
    public String parentId() { return parentId; }
  }

  public static final class VerifiedHuman {
    private final String realmId, realmName, subject, issuer, clientId, clientUuid, nativeSessionId;
    private final Long tenantId;
    private final Set<String> audiences, directGroupIds, realmRoles;
    private final Map<String, CurrentGroup> currentGroups;
    private final Map<String, Set<String>> clientRoles;
    private VerifiedHuman(String realmId, String realmName, String subject, String issuer, String clientId,
        String clientUuid, String nativeSessionId, Long tenantId, Set<String> audiences, Set<String> directGroupIds,
        Map<String, CurrentGroup> currentGroups, Set<String> realmRoles, Map<String, Set<String>> clientRoles) {
      this.realmId = realmId; this.realmName = realmName; this.subject = subject; this.issuer = issuer;
      this.clientId = clientId; this.clientUuid = clientUuid; this.nativeSessionId = nativeSessionId; this.tenantId = tenantId;
      this.audiences = audiences; this.directGroupIds = directGroupIds; this.currentGroups = currentGroups;
      this.realmRoles = realmRoles; this.clientRoles = clientRoles;
    }
    public String realmId() { return realmId; }
    public String realmName() { return realmName; }
    public String subject() { return subject; }
    public String issuer() { return issuer; }
    public String clientId() { return clientId; }
    public String clientUuid() { return clientUuid; }
    public String nativeSessionId() { return nativeSessionId; }
    public Long tenantId() { return tenantId; }
    public Set<String> audiences() { return audiences; }
    public Set<String> directGroupIds() { return directGroupIds; }
    public Map<String, CurrentGroup> currentGroups() { return currentGroups; }
    public Set<String> realmRoles() { return realmRoles; }
    public Map<String, Set<String>> clientRoles() { return clientRoles; }
  }

  private CurrentNativeHumanIdentity() {}
}
