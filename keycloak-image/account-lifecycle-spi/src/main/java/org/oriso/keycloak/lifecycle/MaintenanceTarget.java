package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.ws.rs.ClientErrorException;
import java.util.*;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.jpa.entities.UserEntity;

/** Current scalar native state and immutable committed provenance; never a generic user query. */
final class MaintenanceTarget {
  private final KeycloakSession session;
  private final LifecycleAuthorization auth;
  private final Map<String, Set<String>> mappings;

  MaintenanceTarget(KeycloakSession session, LifecycleAuthorization auth,
      Map<String, Set<String>> mappings) {
    this.session = session;
    this.auth = auth;
    this.mappings = mappings;
  }

  JsonNode read(MaintenanceRequest request) {
    return read(request, null, null);
  }

  JsonNode read(MaintenanceRequest request, GeneralPolicy policy, String rawHumanBearer) {
    return read(request, policy, rawHumanBearer, null);
  }

  JsonNode readOtpSelf(MaintenanceRequest request, GeneralPolicy policy, String rawHumanBearer) {
    if (policy == null || !"SELF".equals(request.target().path("origin").path("kind").asText())) deny();
    return read(request, policy, rawHumanBearer, "otp.read");
  }

  JsonNode readOtpSelfAppSetup(MaintenanceRequest request, GeneralPolicy policy, String rawHumanBearer) {
    if (policy == null || !"SELF".equals(request.target().path("origin").path("kind").asText())) deny();
    return read(request, policy, rawHumanBearer, "otp.app-setup");
  }

  JsonNode readOtpSelfDelete(MaintenanceRequest request, GeneralPolicy policy, String rawHumanBearer) {
    if (policy == null || !"SELF".equals(request.target().path("origin").path("kind").asText())) deny();
    return read(request, policy, rawHumanBearer, "otp.delete");
  }

  JsonNode readOtpSelfEmailFinish(MaintenanceRequest request, GeneralPolicy policy, String rawHumanBearer) {
    if (policy == null || !"SELF".equals(request.target().path("origin").path("kind").asText())) deny();
    return read(request, policy, rawHumanBearer, "otp.email-finish");
  }

  JsonNode readOtpSelfEmailStart(MaintenanceRequest request, GeneralPolicy policy, String rawHumanBearer) {
    if (policy == null || !"SELF".equals(request.target().path("origin").path("kind").asText())) deny();
    return read(request, policy, rawHumanBearer, "otp.email-start");
  }

  private JsonNode read(MaintenanceRequest request, GeneralPolicy policy, String rawHumanBearer,
      String otpOperation) {
    // Domain deletion and independently native-verified ordinary self are separate authorities.
    var origin = request.target().path("origin");
    boolean humanSelf = "SELF".equals(origin.path("kind").asText());
    if (!("DELETION".equals(origin.path("kind").asText()) || humanSelf && policy != null)) deny();
    var realm = session.getContext().getRealm();
    if (realm.getComponentsStream(realm.getId(), "org.keycloak.storage.UserStorageProvider")
        .findAny().isPresent()) deny();
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var lockedRealm = em.find(RealmEntity.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
    if (lockedRealm == null) deny();
    em.refresh(lockedRealm);
    // A deleted native UUID cannot inherit an earlier committed human provenance.
    if (!em.createNativeQuery(
        "select ID from ORISO_ACCOUNT_MAINTENANCE_OP where REALM_ID = :realm and ACCOUNT_ID = :account and COMMAND = 'delete' for update")
        .setParameter("realm", realm.getId()).setParameter("account", request.accountId())
        .getResultList().isEmpty()) deny();
    var attempts = em.createQuery(
        "select a from AccountLifecycleAttempt a where a.realmId = :realm and a.accountId = :account",
        AccountLifecycleAttempt.class)
        .setParameter("realm", realm.getId()).setParameter("account", request.accountId())
        .setLockMode(LockModeType.PESSIMISTIC_WRITE).getResultList();
    if (attempts.size() != 1) deny();
    var row = attempts.get(0);
    em.refresh(row);
    if (!"COMMITTED".equals(row.state) || !"commit".equals(row.terminalOperation)
        || row.terminalReceipt == null || row.creationProof == null
        || !"backend-account-create".equals(row.ownerClient)
        || !auth.creatorSubject.equals(row.ownerSubject)) deny();
    var scope = parse(row.scope);
    LifecycleGroups.scope(scope);
    if (!scope.path("tenantId").equals(request.target().path("tenantId"))) deny();
    var expectedRoles = mappings.get(scope.path("initialGroup").asText());
    if (expectedRoles == null) deny();
    if (humanSelf) {
      if ("otp.delete".equals(otpOperation)) policy.requireSelfOtpDelete(session, request, rawHumanBearer);
      else if ("otp.app-setup".equals(otpOperation)) policy.requireSelfOtpAppSetup(session, request, rawHumanBearer);
      else if ("otp.email-finish".equals(otpOperation)) policy.requireSelfOtpEmailFinish(session, request, rawHumanBearer);
      else if ("otp.email-start".equals(otpOperation)) policy.requireSelfOtpEmailStart(session, request, rawHumanBearer);
      else if ("otp.read".equals(otpOperation)) policy.requireSelfOtpRead(session, request, rawHumanBearer);
      else policy.requireSelf(session, request, rawHumanBearer);
    }
    var entity = em.find(UserEntity.class, request.accountId(), LockModeType.PESSIMISTIC_WRITE);
    if (entity == null) deny();
    em.refresh(entity);
    var current = lockedSnapshot(em, request.accountId());
    var group = LifecycleGroups.group(session, realm, scope.path("initialGroup").asText(), expectedRoles);
    if (!group.getId().equals(row.groupId)
        || !LifecycleAuthorization.equal(row.roleFingerprint,
            auth.mac("initial-roles", JSON.valueToTree(new TreeSet<>(expectedRoles))))) deny();
    // Positive human-profile membership is required. Absence of a service-account link is insufficient.
    if (!realm.getId().equals(current.path("realmId").asText())
        || !current.path("federationLink").isNull()
        || !current.path("serviceAccountClientLink").isNull()
        || !current.path("roles").isEmpty()
        || current.path("groups").size() != 1
        || !group.getId().equals(current.path("groups").path(0).asText())
        || request.accountId().equals(auth.creatorSubject)
        || request.accountId().equals(auth.adminSubject)) deny();
    var attributes = current.path("attributes");
    var tenants = attributes.path("tenantId");
    JsonNode actualTenant = tenants.isMissingNode() || tenants.isEmpty() ? JSON.nullNode() : tenants.path(0);
    if ((!tenants.isMissingNode() && tenants.size() != 1)
        || !scope.path("tenantId").equals(actualTenant)) deny();
    var state = JSON.createObjectNode();
    state.set("account", current);
    state.put("realmId", realm.getId());
    state.put("provenance", row.id);
    state.put("groupId", group.getId());
    state.set("effectiveRoles", JSON.valueToTree(new TreeSet<>(expectedRoles)));
    var body = JSON.createObjectNode();
    for (String field : List.of("id", "username", "email", "firstName", "lastName", "enabled", "emailVerified"))
      body.set(field, current.path(field));
    body.set("tenantId", actualTenant);
    var locale = attributes.path("locale");
    if (!locale.isMissingNode() && locale.size() != 1) deny();
    body.set("preferredLanguage", locale.isMissingNode() ? JSON.nullNode() : locale.path(0));
    body.set("effectiveRoles", JSON.valueToTree(new TreeSet<>(expectedRoles)));
    boolean passwordChange = false;
    for (var action : current.path("requiredActions"))
      if (UserModel.RequiredAction.UPDATE_PASSWORD.name().equals(action.asText())) passwordChange = true;
    body.put("passwordChangeRequired", passwordChange);
    body.put("state", auth.mac("maintenance-state", state));
    return body;
  }

  void delete(MaintenanceRequest request) {
    var current = read(request);
    if (!LifecycleAuthorization.equal(request.expectedState(), current.path("state").asText())) conflict();
    var realm = session.getContext().getRealm();
    var user = session.users().getUserById(realm, request.accountId());
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) {
      cache.evict(realm, user);
      user = session.users().getUserById(realm, request.accountId());
    }
    if (user == null || !session.users().removeUser(realm, user)) conflict();
  }

  void locale(MaintenanceRequest request, GeneralPolicy policy, String rawHumanBearer) {
    var current = read(request, policy, rawHumanBearer);
    if (!LifecycleAuthorization.equal(request.expectedState(), current.path("state").asText())) conflict();
    var realm = session.getContext().getRealm();
    var user = session.users().getUserById(realm, request.accountId());
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) {
      cache.evict(realm, user);
      user = session.users().getUserById(realm, request.accountId());
    }
    if (user == null) conflict();
    String locale = request.change().path("locale").asText();
    user.setSingleAttribute("locale", locale);
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    em.flush();
    var values = em.createNativeQuery(
        "select VALUE, LONG_VALUE from USER_ATTRIBUTE where USER_ID = :account and NAME = 'locale' for update")
        .setParameter("account", request.accountId()).getResultList();
    if (values.size() != 1) conflict();
    var stored = (Object[]) values.get(0);
    if (!locale.equals(scalarText(stored[0])) || stored[1] != null) conflict();
  }

  private JsonNode lockedSnapshot(EntityManager em, String id) {
    // Current locking reads must supply the values we validate. A normal model read
    // can retain an older MariaDB REPEATABLE READ view after these locks are acquired.
    // Keep scalar results: managed children break Keycloak's bulk-delete ordering.
    var rows =
        em.createNativeQuery(
                "select ID, USERNAME, EMAIL, FIRST_NAME, LAST_NAME, EMAIL_VERIFIED, ENABLED,"
                    + " FEDERATION_LINK, SERVICE_ACCOUNT_CLIENT_LINK, REALM_ID from USER_ENTITY"
                    + " where ID = :id for update")
            .setParameter("id", id)
            .getResultList();
    if (rows.size() != 1) conflict();
    var base = (Object[]) rows.get(0);
    var result = JSON.createObjectNode();
    String[] names = {"id", "username", "email", "firstName", "lastName"};
    for (int i = 0; i < names.length; i++) result.put(names[i], scalarText(base[i]));
    result.put("emailVerified", scalarBoolean(base[5]));
    result.put("enabled", scalarBoolean(base[6]));
    result.put("federationLink", scalarText(base[7]));
    result.put("serviceAccountClientLink", scalarText(base[8]));
    result.put("realmId", scalarText(base[9]));
    var credentials = result.putArray("credentials");
    for (Object item :
        em.createNativeQuery(
                "select ID, TYPE, CREDENTIAL_DATA, SECRET_DATA, USER_LABEL, CREATED_DATE, PRIORITY,"
                    + " SALT, VERSION from CREDENTIAL where USER_ID = :id order by ID for update")
            .setParameter("id", id)
            .getResultList()) {
      var credential = credentials.addArray();
      for (Object value : (Object[]) item) {
        if (value instanceof java.sql.Clob) credential.add(scalarText(value));
        else if (value instanceof java.sql.Blob blob) {
          try {
            credential.add(
                Base64.getEncoder()
                    .encodeToString(blob.getBytes(1, Math.toIntExact(blob.length()))));
          } catch (java.sql.SQLException failure) {
            throw new IllegalStateException("Stored credential unavailable");
          }
        } else credential.add(JSON.valueToTree(value));
      }
    }
    var attributes = new TreeMap<String, List<String>>();
    for (Object item :
        em.createNativeQuery(
                "select NAME, VALUE, LONG_VALUE "
                    + "from USER_ATTRIBUTE where USER_ID = :id order by NAME, ID for update")
            .setParameter("id", id)
            .getResultList()) {
      var attribute = (Object[]) item;
      if (attribute[1] != null && attribute[2] != null) conflict();
      attributes
          .computeIfAbsent(scalarText(attribute[0]), ignored -> new ArrayList<>())
          .add(scalarText(attribute[2] == null ? attribute[1] : attribute[2]));
    }
    result.set("attributes", JSON.valueToTree(attributes));
    for (String[] mapping :
        new String[][] {
          {"requiredActions", "USER_REQUIRED_ACTION", "REQUIRED_ACTION"},
          {"roles", "USER_ROLE_MAPPING", "ROLE_ID"},
          {"groups", "USER_GROUP_MEMBERSHIP", "GROUP_ID"}
        }) {
      var values = result.putArray(mapping[0]);
      // Table and column identifiers are fixed pinned schema names, never input.
      for (Object value :
          em.createNativeQuery(
                  "select "
                      + mapping[2]
                      + " from "
                      + mapping[1]
                      + " where USER_ID = :id order by "
                      + mapping[2]
                      + " for update")
              .setParameter("id", id)
              .getResultList()) values.add(scalarText(value));
    }
    // Only its keyed digest is stored. Credential material never leaves this method's caller.
    return result;
  }

  private static String scalarText(Object value) {
    if (value == null) return null;
    if (value instanceof java.sql.Clob clob) {
      try {
        return clob.getSubString(1, Math.toIntExact(clob.length()));
      } catch (java.sql.SQLException failure) {
        throw new IllegalStateException("Stored text unavailable");
      }
    }
    return value.toString();
  }

  private static boolean scalarBoolean(Object value) {
    if (value instanceof Boolean flag) return flag;
    if (value instanceof Number flag) return flag.intValue() != 0;
    throw new IllegalStateException("Unsupported stored boolean");
  }

  private static void conflict() {
    throw new ClientErrorException("Current account state conflicts", 409);
  }
}
