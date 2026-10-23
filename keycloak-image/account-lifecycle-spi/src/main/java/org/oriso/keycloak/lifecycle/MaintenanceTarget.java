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
  private final GeneralPolicy configuredPolicy;

  MaintenanceTarget(KeycloakSession session, LifecycleAuthorization auth,
      Map<String, Set<String>> mappings) {
    this(session,auth,mappings,null);
  }
  MaintenanceTarget(KeycloakSession session,LifecycleAuthorization auth,Map<String,Set<String>> mappings,GeneralPolicy configuredPolicy) {
    this.configuredPolicy=configuredPolicy;
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
    if (attempts.isEmpty() && !humanSelf) return readAdopted(request);
    if (attempts.size() != 1) deny();
    var row = attempts.get(0);
    em.refresh(row);
    if (!"COMMITTED".equals(row.state) || !"commit".equals(row.terminalOperation)
        || row.terminalReceipt == null || row.creationProof == null || row.terminalDigest == null
        || !"backend-account-create".equals(row.ownerClient)
        || !auth.creatorSubject.equals(row.ownerSubject)) deny();
    var scope = parse(row.scope);
    LifecycleGroups.scope(scope);
    if (!scope.path("tenantId").equals(request.target().path("tenantId"))) deny();
    var expectedRoles = mappings.get(scope.path("initialGroup").asText());
    if (expectedRoles == null) deny();
    OrdinaryAccountOperations.verifyCommitted(auth,realm.getName(),row,scope);
    var provenance=JSON.createObjectNode();provenance.put("attempt",row.id);provenance.put("creationProof",row.creationProof);
    provenance.put("terminalReceipt",row.terminalReceipt);provenance.set("scope",scope);
    var lineage=MaintenanceLineage.ordinaryExisting(session,auth,request.accountId(),auth.mac("maintenance-provenance/v1",provenance),
        scope.path("initialGroup").asText(),row.groupId,expectedRoles,scope.path("tenantId"));
    String currentPath=scope.path("initialGroup").asText();String currentGroup=row.groupId;
    if(lineage!=null){
      var frozen=lineage.nativeProfile();currentPath=text(frozen,"groupPath",512,false);currentGroup=text(frozen,"groupId",255,false);
      var desiredRoles=HumanPolicyJson.strings(frozen.path("realmRoles"),1,10,255);
      if(!desiredRoles.equals(mappings.get(currentPath))||!frozen.path("clientRoles").isObject()||!frozen.path("clientRoles").isEmpty()
          ||LifecycleGroups.allowedKind(desiredRoles)==null
          ||!lineage.tenant().equals(scope.path("tenantId")))deny();
      expectedRoles=desiredRoles;
    }
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
    var originalRoles=mappings.get(scope.path("initialGroup").asText());
    var original=LifecycleGroups.group(session,realm,scope.path("initialGroup").asText(),originalRoles);
    if(!original.getId().equals(row.groupId)||!LifecycleAuthorization.equal(row.roleFingerprint,
        auth.mac("initial-roles",JSON.valueToTree(new TreeSet<>(originalRoles)))))deny();
    var group = LifecycleGroups.group(session, realm, currentPath, expectedRoles);
    if(!group.getId().equals(currentGroup))deny();
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
    if(lineage!=null)state.put("lineageDigest",lineage.digest());
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

  private JsonNode readAdopted(MaintenanceRequest request) {
    if(configuredPolicy==null||!"DELETION".equals(request.target().path("origin").path("kind").asText()))deny();
    var adoption=configuredPolicy.adoptedAccounts.get(request.accountId());if(adoption==null)deny();
    var profile=configuredPolicy.profile(adoption.profileId(),adoption.profileVersion());
    if(!profile.realmRoles.equals(Set.of("user"))||!profile.realmRoles.equals(mappings.get(profile.path))
        ||!profile.clientRoles.isEmpty()||configuredPolicy.nativePolicy.subjects.contains(request.accountId())
        ||!session.getContext().getRealm().getId().equals(configuredPolicy.nativePolicy.realmId))deny();
    var realm=session.getContext().getRealm();var em=CurrentNativeHumanIdentity.entityManager(session);
    configuredPolicy.validateProfile(session,profile);
    var group=LifecycleGroups.group(session,realm,profile.path,profile.realmRoles);
    if(!group.getId().equals(profile.groupId))deny();
    var current=lockedSnapshot(em,request.accountId());
    if(!realm.getId().equals(current.path("realmId").asText())||!current.path("federationLink").isNull()
        ||!current.path("serviceAccountClientLink").isNull()||!current.path("roles").isEmpty()
        ||current.path("groups").size()!=1||!profile.groupId.equals(current.path("groups").path(0).asText()))deny();
    var values=current.path("attributes").path("tenantId");
    JsonNode tenant=values.isMissingNode()||values.isEmpty()?JSON.nullNode():values.path(0);
    if(!values.isMissingNode()&&values.size()!=1||!tenant.equals(request.target().path("tenantId"))
        ||tenant.isNull()&&!profile.allowUnassignedTenant)deny();
    var baseline=MaintenanceAdoption.prepare(session,auth,request.accountId(),"ORDINARY",profile.id,profile.version,profile.snapshot,tenant);
    if(!baseline.tenant().equals(tenant))deny();baseline.checked(session);
    var state=JSON.createObjectNode();state.put("realmId",realm.getId());state.set("account",current);state.put("provenance",baseline.provenance());
    state.put("groupId",profile.groupId);state.set("effectiveRoles",JSON.valueToTree(new TreeSet<>(profile.realmRoles)));
    var result=JSON.createObjectNode();
    for(String field:List.of("id","username","email","firstName","lastName","enabled","emailVerified"))result.set(field,current.path(field));
    result.set("tenantId",tenant);var locale=current.path("attributes").path("locale");if(!locale.isMissingNode()&&locale.size()!=1)deny();
    result.set("preferredLanguage",locale.isMissingNode()?JSON.nullNode():locale.path(0));
    result.set("effectiveRoles",JSON.valueToTree(new TreeSet<>(profile.realmRoles)));boolean required=false;
    for(var action:current.path("requiredActions"))if("UPDATE_PASSWORD".equals(action.asText()))required=true;
    result.put("passwordChangeRequired",required);result.put("state",auth.mac("maintenance-state",state));return result;
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

  void profile(MaintenanceRequest request, GeneralPolicy policy, String rawHumanBearer) {
    var current = read(request, policy, rawHumanBearer);
    if (!LifecycleAuthorization.equal(request.expectedState(), current.path("state").asText())) conflict();
    // This first profile capability changes names only. Email enrollment keeps its separate proof.
    if (!request.change().path("email").equals(current.path("email"))) deny();
    var realm = session.getContext().getRealm();
    var user = session.users().getUserById(realm, request.accountId());
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) {
      cache.evict(realm, user);
      user = session.users().getUserById(realm, request.accountId());
    }
    if (user == null) conflict();
    user.setFirstName(request.change().path("firstName").textValue());
    user.setLastName(request.change().path("lastName").textValue());
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    em.flush();
    var fresh = lockedSnapshot(em, request.accountId());
    for (String field : List.of("firstName", "lastName", "email"))
      if (!request.change().path(field).equals(fresh.path(field))) conflict();
  }

  void password(MaintenanceRequest request, GeneralPolicy policy, String rawHumanBearer) {
    var current = read(request, policy, rawHumanBearer);
    if (!LifecycleAuthorization.equal(request.expectedState(), current.path("state").asText())) conflict();
    // Temporary-password/reset workflows have separate causal authority; this is current SELF.
    if (request.change().path("temporary").asBoolean()) deny();
    var realm = session.getContext().getRealm();
    var user = session.users().getUserById(realm, request.accountId());
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) {
      cache.evict(realm, user);
      user = session.users().getUserById(realm, request.accountId());
    }
    if (user == null) conflict();
    if ("self-password".equals(request.command())
        && !user.credentialManager().isValid(
            UserCredentialModel.password(request.change().path("currentPassword").textValue())))
      throw new jakarta.ws.rs.BadRequestException("Current password was not accepted");
    String password = request.change().path("password").textValue();
    try {
      if (session.getProvider(org.keycloak.policy.PasswordPolicyManagerProvider.class)
          .validate(realm, user, password) != null) bad();
      request.requireEffectDeadline();
      if (!user.credentialManager().updateCredential(UserCredentialModel.password(password))) bad();
      user.removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
      session.getProvider(JpaConnectionProvider.class).getEntityManager().flush();
    } catch (org.keycloak.models.ModelException invalid) {
      throw new jakarta.ws.rs.BadRequestException("Password validation failed");
    }
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
