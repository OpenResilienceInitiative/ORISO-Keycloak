package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.*;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Supplier;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.admin.*;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.userprofile.*;

@jakarta.ws.rs.ext.Provider
@jakarta.enterprise.inject.Vetoed
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public final class AccountLifecycleResource implements RealmResourceProvider {
  private final KeycloakSession session;
  private final LifecycleAuthorization auth;
  private final Map<String, Set<String>> mappings;

  // Only the protected resource's private policy supplies this internal binding.
  // Ordinary HTTP requests always use the null-policy path below.
  record LifecycleBinding(
      String rowId, String ownerClient, String ownerSubject, JsonNode scope,
      String creationFingerprint, String groupId, String roleFingerprint) {
    LifecycleBinding {
      scope = scope.deepCopy();
    }
    @Override public JsonNode scope() { return scope.deepCopy(); }
  }

  interface LifecyclePolicy {
    LifecycleBinding binding();
    GroupModel approvedGroup(RealmModel realm);
    void verifyCreate(JsonNode internalBody);
    String commandDigest();
    void before(String command, AccountLifecycleAttempt attempt, EntityManager em);
    void after(String command, AccountLifecycleAttempt attempt, EntityManager em);
  }

  AccountLifecycleResource(
      KeycloakSession session, LifecycleAuthorization auth, Map<String, Set<String>> mappings) {
    this.session = session;
    this.auth = auth;
    this.mappings = mappings;
  }

  @PUT
  @Path("v1/attempts/{attempt}")
  public Response create(
      @PathParam("attempt") String attempt,
      byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof) {
    return guarded(() -> execute("create", attempt, raw, proof));
  }

  @POST
  @Path("v1/attempts/{attempt}/owned-read")
  public Response read(
      @PathParam("attempt") String attempt,
      byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof) {
    return guarded(() -> execute("owned-read", attempt, raw, proof));
  }

  @POST
  @Path("v1/attempts/{attempt}/recover")
  public Response recover(
      @PathParam("attempt") String attempt,
      byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof) {
    return guarded(() -> execute("recover", attempt, raw, proof));
  }

  @POST
  @Path("v1/attempts/{attempt}/commit")
  public Response commit(
      @PathParam("attempt") String attempt,
      byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof) {
    return guarded(() -> execute("commit", attempt, raw, proof));
  }

  @POST
  @Path("v1/attempts/{attempt}/compensate")
  public Response compensate(
      @PathParam("attempt") String attempt,
      byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof) {
    return guarded(() -> execute("compensate", attempt, raw, proof));
  }

  private Response guarded(Supplier<Response> command) {
    try {
      return command.get();
    } catch (AvailabilityConflict failure) {
      session.getTransactionManager().setRollbackOnly();
      return Response.status(409)
          .type(MediaType.APPLICATION_JSON)
          .entity(Map.of("code", failure.reason.name()))
          .header("Cache-Control", "no-store")
          .build();
    } catch (WebApplicationException failure) {
      session.getTransactionManager().setRollbackOnly();
      throw new WebApplicationException(
          Response.status(failure.getResponse().getStatus())
              .type(MediaType.APPLICATION_JSON)
              .entity(Map.of("error", "Lifecycle request rejected"))
              .header("Cache-Control", "no-store")
              .build());
    } catch (RuntimeException failure) {
      var types = new ArrayList<String>();
      for (Throwable cause = failure; cause != null && types.size() < 8; cause = cause.getCause()) {
        var frames = cause.getStackTrace();
        types.add(cause.getClass().getName() + (frames.length == 0 ? "" : " @ " + frames[0]));
        if (cause instanceof org.hibernate.TransientPropertyValueException reference) {
          // Schema identifiers only; exception messages can contain account data.
          types.add(reference.getPropertyOwnerEntityName() + "." + reference.getPropertyName());
          types.add(reference.getTransientEntityName());
        }
      }
      org.jboss.logging.Logger.getLogger(AccountLifecycleResource.class)
          .errorf("Lifecycle transaction rolled back: %s", String.join(" -> ", types));
      session.getTransactionManager().setRollbackOnly();
      throw new WebApplicationException(
          Response.status(503)
              .type(MediaType.APPLICATION_JSON)
              .entity(Map.of("error", "Lifecycle request could not complete"))
              .header("Cache-Control", "no-store")
              .build());
    }
  }

  private Response execute(String command, String attemptId, byte[] raw, String proof) {
    uuid(attemptId);
    var body = parse(raw);
    String operation =
        switch (command) {
          case "recover" -> "account.creation-recover";
          default -> "account." + command;
        };
    String actor =
        auth.require(
            session, proof, operation, "create".equals(command) ? "PUT" : "POST", attemptId, body);
    return execute(command, attemptId, body, actor, null);
  }

  Response executeProtected(
      String command, String attemptId, JsonNode neutralBody, String checkedActor,
      LifecyclePolicy policy) {
    // Each protected command is enabled only with its own public HTTP tracer.
    if (policy == null || !Set.of("create", "owned-read", "commit", "recover", "compensate").contains(command)
        || !("ACCOUNT_CREATE".equals(checkedActor)
            || Set.of("recover", "compensate").contains(command) && "ACCOUNT_ADMIN".equals(checkedActor))) deny();
    return guarded(() -> execute(command, attemptId, neutralBody, checkedActor, policy));
  }

  private Response execute(
      String command, String attemptId, JsonNode body, String actor, LifecyclePolicy policy) {
    uuid(attemptId);
    var identity = body.path("identity");
    fields(identity, "scope", "creationFingerprint");
    var scope = identity.path("scope");
    var binding = policy == null ? null : policy.binding();
    if (binding == null) LifecycleGroups.scope(scope);
    else if (!canonical(binding.scope()).equals(canonical(scope))
        || !LifecycleAuthorization.equal(binding.creationFingerprint(), identity.path("creationFingerprint").asText())) deny();
    hex(text(identity, "creationFingerprint", 64, false));
    var realm = session.getContext().getRealm();
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var locked = em.find(RealmEntity.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
    if (locked == null) conflict();
    em.refresh(locked);
    var row =
        em.find(
            AccountLifecycleAttempt.class,
            binding == null ? realm.getId() + ":" + attemptId : binding.rowId(),
            LockModeType.PESSIMISTIC_WRITE);
    if (row != null) {
      if (!(binding == null ? "backend-account-create" : binding.ownerClient()).equals(row.ownerClient)
          || !(binding == null ? auth.creatorSubject : binding.ownerSubject()).equals(row.ownerSubject)
          || !canonical(scope).equals(row.scope)
          || !LifecycleAuthorization.equal(
              row.creationFingerprint, identity.path("creationFingerprint").asText())) deny();
    }
    if ("create".equals(command)) return create(body, realm, row, attemptId, em, policy);
    if ("recover".equals(command)) return recover(body, realm, row, attemptId, em, policy);
    if (row == null) deny();
    if ("owned-read".equals(command)) {
      fields(body, "identity", "execution", "accountId", "creationProof");
      owned(body, row);
      if (!"OPEN".equals(row.state)) conflict();
      if (policy != null) policy.before("owned-read", row, em);
      var user = integrity(row, realm, LifecycleGroups.pending(session, realm));
      if (user == null) conflict();
      return ok(projection(user), 200);
    }
    boolean commit = "commit".equals(command);
    fields(
        body,
        "identity",
        "execution",
        "accountId",
        "creationProof",
        commit ? "localCommit" : "localCleanup");
    outcome(body.path(commit ? "localCommit" : "localCleanup"));
    owned(body, row);
    String digest = policy == null ? auth.mac("payload", body) : policy.commandDigest();
    if (row.terminalOperation != null) {
      if (command.equals(row.terminalOperation)
          && LifecycleAuthorization.equal(digest, row.terminalDigest)) return result(row, 200);
      conflict();
    }
    if (commit) {
      if (!"OPEN".equals(row.state)) conflict();
      if (policy != null) policy.before("commit", row, em);
      var group = policy == null ? approvedGroup(realm, scope) : policy.approvedGroup(realm);
      var pending = LifecycleGroups.pending(session, realm);
      var roles = mappings.get(scope.path("initialGroup").asText());
      if (!group.getId().equals(row.groupId)
          || !(binding == null ? auth.mac("initial-roles", JSON.valueToTree(new TreeSet<>(roles)))
                  : binding.roleFingerprint())
              .equals(row.roleFingerprint)) conflict();
      var user = integrity(row, realm, pending);
      if (user == null) conflict();
      user.user().leaveGroup(pending);
      user.user().joinGroup(group);
      user.user().setEnabled(true);
      em.flush();
      // Native joinGroup can use an older consistent-read view. Require its actual
      // current effect before saving a terminal receipt; mismatch rolls back all writes.
      var groups =
          em.createNativeQuery(
                  "select GROUP_ID from USER_GROUP_MEMBERSHIP where USER_ID = :id for update")
              .setParameter("id", row.accountId)
              .getResultList();
      if (groups.size() != 1 || !row.groupId.equals(groups.get(0))) conflict();
      row.state = "COMMITTED";
      audit(realm, actor, OperationType.UPDATE, row.accountId);
    } else {
      if (!Set.of("OPEN", "RECOVERY_CLAIMED", "ABANDONED").contains(row.state)) conflict();
      if (policy != null) policy.before("compensate", row, em);
      if (!"ABANDONED".equals(row.state)) {
        var user = integrity(row, realm, LifecycleGroups.pending(session, realm));
        if (user != null && !session.users().removeUser(realm, user.user())) conflict();
        row.state = "COMPENSATED";
        audit(realm, actor, OperationType.DELETE, row.accountId);
      }
    }
    row.terminalOperation = command;
    row.terminalDigest = digest;
    if (row.terminalReceipt == null)
      row.terminalReceipt = auth.receipt("terminal-receipt", receipt(row, command, digest));
    if (policy != null) {
      if (row.terminalReceipt.getBytes(StandardCharsets.UTF_8).length > 16000) bad();
      policy.after(command, row, em);
    }
    em.flush();
    return result(row, 200);
  }

  private Response create(
      JsonNode body,
      RealmModel realm,
      AccountLifecycleAttempt row,
      String attempt,
      EntityManager em,
      LifecyclePolicy policy) {
    fields(body, "identity", "execution", "account");
    execution(body.path("execution"));
    if (number(body.path("execution"), "generation", false) != 0) conflict();
    var account = body.path("account");
    fields(
        account,
        "username",
        "email",
        "firstName",
        "lastName",
        "preferredLanguage",
        "password",
        "passwordTemporary");
    String username = text(account, "username", 255, false);
    for (var key : List.of("email", "firstName", "lastName")) text(account, key, 255, true);
    text(account, "preferredLanguage", 20, true);
    // Passwords are opaque strings; spaces/newlines are policy input, never normalized.
    var passwordNode = account.path("password");
    if (!passwordNode.isNull()
        && (!passwordNode.isTextual() || passwordNode.asText().length() > 4096)) bad();
    if (!account.path("passwordTemporary").isBoolean()) bad();
    if (policy == null) {
      var original = JSON.createObjectNode();
      original.set("scope", body.path("identity").path("scope"));
      original.set("account", account);
      String fingerprint = auth.mac("creation-payload", original);
      if (!LifecycleAuthorization.equal(
          fingerprint, body.path("identity").path("creationFingerprint").asText())) deny();
    } else policy.verifyCreate(body);
    if (row != null) {
      if (!"OPEN".equals(row.state)
          || !row.executionId.equals(body.path("execution").path("executionId").asText())
          || row.generation != 0) conflict();
      if (policy != null) policy.before("create", row, em);
      return result(row, 200);
    }
    requireLocalRealm(realm);
    if (policy != null) policy.before("create", null, em);
    var group = policy == null ? approvedGroup(realm, body.path("identity").path("scope")) : policy.approvedGroup(realm);
    var pending = LifecycleGroups.pending(session, realm);
    String email = text(account, "email", 255, true);
    if (session.users().getUserByUsername(realm, username) != null)
      throw new AvailabilityConflict(Unavailable.USERNAME_NOT_AVAILABLE);
    if (email != null && session.users().getUserByEmail(realm, email) != null)
      throw new AvailabilityConflict(Unavailable.EMAIL_NOT_AVAILABLE);
    row = newRow(body.path("identity"), realm, group, attempt, policy);
    row.createExecution = body.path("execution").path("executionId").asText();
    row.executionId = row.createExecution;
    row.state = "OPEN";
    em.persist(row);
    em.flush();
    Map<String, Object> attributes = new HashMap<>();
    attributes.put("username", username);
    for (var field : List.of("email", "firstName", "lastName"))
      if (!account.path(field).isNull()) attributes.put(field, account.path(field).asText());
    UserModel user;
    try {
      var provider = session.getProvider(UserProfileProvider.class);
      var profile = provider.create(UserProfileContext.USER_API, attributes);
      profile.validate();
      user = profile.create();
      if (user.getFederationLink() != null || user.getServiceAccountClientLink() != null) deny();
      user.setEnabled(false);
      user.setEmailVerified(true);
      if (Set.of("ASKER", "ANONYMOUS")
              .contains(body.path("identity").path("scope").path("registrationKind").asText())
          && (user.getEmail() == null || user.getEmail().isBlank())) {
        String suffix = System.getenv("ORISO_IDENTITY_DUMMY_EMAIL_SUFFIX");
        if (suffix == null || !suffix.matches("@[A-Za-z0-9][A-Za-z0-9.-]{1,250}"))
          throw new ServiceUnavailableException();
        attributes.put("email", user.getId() + suffix);
        var completed = provider.create(UserProfileContext.USER_API, attributes, user);
        completed.validate();
        completed.update(false);
      }
      user.setSingleAttribute("userId", user.getId());
      String decoded = URLDecoder.decode(username, StandardCharsets.UTF_8);
      user.setSingleAttribute("username", decoded);
      user.setSingleAttribute("userName", decoded);
      var tenant = body.path("identity").path("scope").path("tenantId");
      if (!tenant.isNull()) user.setSingleAttribute("tenantId", tenant.asText());
      user.setSingleAttribute(
          "locale",
          account.path("preferredLanguage").isNull()
              ? "de"
              : account.path("preferredLanguage").asText());
      // Profile creation adds realm defaults. Only an empty default marker may exist;
      // never grant or silently strip inherited/client human privileges.
      var direct = user.getRoleMappingsStream().toList();
      var defaultRole = realm.getDefaultRole();
      for (var role : direct) {
        if (defaultRole == null
            || !role.getId().equals(defaultRole.getId())
            || role.getCompositesStream().findAny().isPresent()) deny();
        user.deleteRoleMapping(role);
      }
      if (user.getGroupsStream().findAny().isPresent()) deny();
      user.joinGroup(pending);
      if (!passwordNode.isNull()) {
        String password = passwordNode.asText();
        if (session.getProvider(PasswordPolicyManagerProvider.class).validate(realm, user, password)
            != null) bad();
        if (!user.credentialManager().updateCredential(UserCredentialModel.password(password)))
          bad();
        if (account.path("passwordTemporary").asBoolean())
          user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        else user.removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
      }
    } catch (ValidationException | ModelException failure) {
      throw new BadRequestException("Account validation failed");
    }
    row.accountId = user.getId();
    em.flush();
    row.profileFingerprint = auth.mac("pending-profile", lockedSnapshot(em, user.getId()));
    var creation = JSON.createObjectNode();
    creation.put("v", 1);
    creation.put("realmName", realm.getName());
    creation.put("realmId", row.realmId);
    creation.put("attemptId", row.attemptId);
    creation.put("accountId", row.accountId);
    creation.put("ownerClient", row.ownerClient);
    creation.put("ownerSubject", row.ownerSubject);
    creation.set("scope", body.path("identity").path("scope"));
    creation.put("initialGroupId", row.groupId);
    creation.put("initialRoleFingerprint", row.roleFingerprint);
    creation.put("creationFingerprint", row.creationFingerprint);
    row.creationProof = auth.creationReceipt(creation);
    if (row.creationProof.getBytes(StandardCharsets.UTF_8).length > 16384) bad();
    audit(realm, "ACCOUNT_CREATE", OperationType.CREATE, user.getId());
    if (policy != null) policy.after("create", row, em);
    em.flush();
    return result(row, 201);
  }

  private Response recover(
      JsonNode body,
      RealmModel realm,
      AccountLifecycleAttempt row,
      String attempt,
      EntityManager em,
      LifecyclePolicy policy) {
    fields(body, "identity", "expectedGeneration", "recoveryId");
    long expected = number(body, "expectedGeneration", false);
    String recovery = uuid(text(body, "recoveryId", 36, false));
    String digest = policy == null ? auth.mac("payload", body) : policy.commandDigest();
    if (row != null && recovery.equals(row.recoveryId)) {
      if (!LifecycleAuthorization.equal(digest, row.recoveryDigest)
          || row.recoveryExpected == null
          || expected != row.recoveryExpected) conflict();
      return result(row, 200);
    }
    if (row != null && Set.of("COMMITTED", "COMPENSATED", "ABANDONED").contains(row.state)) {
      if (expected != row.generation) conflict();
      return result(row, 200);
    }
    if (policy != null) policy.before("recover", row, em);
    boolean absent = row == null;
    if (absent) {
      if (expected != 0) conflict();
      row =
          newRow(
              body.path("identity"),
              realm,
              policy == null ? approvedGroup(realm, body.path("identity").path("scope")) : null,
              attempt,
              policy);
      row.state = "ABANDONED";
    } else {
      if (expected != row.generation || !Set.of("OPEN", "RECOVERY_CLAIMED").contains(row.state))
        conflict();
      row.state = "RECOVERY_CLAIMED";
    }
    if (expected == Long.MAX_VALUE) conflict();
    row.generation = expected + 1;
    row.executionId = recovery;
    row.recoveryId = recovery;
    row.recoveryExpected = expected;
    row.recoveryDigest = digest;
    row.recoveryReceipt = auth.receipt("recovery-receipt", receipt(row, "recover", digest));
    if ("ABANDONED".equals(row.state))
      row.terminalReceipt = auth.receipt("terminal-receipt", receipt(row, "abandon", digest));
    if (policy != null) {
      if (row.recoveryReceipt.getBytes(StandardCharsets.UTF_8).length > 16000
          || row.terminalReceipt != null
              && row.terminalReceipt.getBytes(StandardCharsets.UTF_8).length > 16000) bad();
      policy.after("recover", row, em);
    }
    if (absent) em.persist(row);
    em.flush();
    return result(row, 200);
  }

  private AccountLifecycleAttempt newRow(
      JsonNode identity, RealmModel realm, GroupModel group, String attempt,
      LifecyclePolicy policy) {
    var binding = policy == null ? null : policy.binding();
    var row = new AccountLifecycleAttempt();
    row.id = binding == null ? realm.getId() + ":" + attempt : binding.rowId();
    row.realmId = realm.getId();
    row.attemptId = attempt;
    row.ownerClient = binding == null ? "backend-account-create" : binding.ownerClient();
    row.ownerSubject = binding == null ? auth.creatorSubject : binding.ownerSubject();
    row.scope = canonical(identity.path("scope"));
    row.groupId = binding == null ? group.getId() : binding.groupId();
    row.roleFingerprint =
        binding != null ? binding.roleFingerprint() : auth.mac(
            "initial-roles",
            JSON.valueToTree(
                new TreeSet<>(mappings.get(identity.path("scope").path("initialGroup").asText()))));
    row.creationFingerprint = identity.path("creationFingerprint").asText();
    return row;
  }

  private void owned(JsonNode body, AccountLifecycleAttempt row) {
    execution(body.path("execution"));
    String account = text(body, "accountId", 255, true),
        proof = text(body, "creationProof", 16384, true);
    if (!Objects.equals(row.accountId, account)
        || !(row.creationProof == null && proof == null
            || LifecycleAuthorization.equal(row.creationProof, proof))) deny();
    if (number(body.path("execution"), "generation", false) != row.generation
        || !row.executionId.equals(body.path("execution").path("executionId").asText())) conflict();
  }

  private GroupModel approvedGroup(RealmModel realm, JsonNode scope) {
    String path = scope.path("initialGroup").asText();
    var roles = mappings.get(path);
    if (roles == null) deny();
    String kind = scope.path("registrationKind").asText();
    if (!Objects.equals(
        "ANONYMOUS".equals(kind) ? "ASKER" : kind, LifecycleGroups.allowedKind(roles))) deny();
    return LifecycleGroups.group(session, realm, path, roles);
  }

  private void requireLocalRealm(RealmModel realm) {
    if (realm
        .getComponentsStream(realm.getId(), "org.keycloak.storage.UserStorageProvider")
        .findAny()
        .isPresent()) deny();
  }

  private record PendingAccount(UserModel user, JsonNode snapshot) {}

  private PendingAccount integrity(
      AccountLifecycleAttempt row, RealmModel realm, GroupModel pending) {
    requireLocalRealm(realm);
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var stored =
        em.find(
            org.keycloak.models.jpa.entities.UserEntity.class,
            row.accountId,
            LockModeType.PESSIMISTIC_WRITE);
    if (stored == null) return null;
    em.refresh(stored);
    var current = lockedSnapshot(em, row.accountId);
    if (!realm.getId().equals(current.path("realmId").asText())
        || current.path("enabled").asBoolean()
        || !current.path("federationLink").isNull()
        || !current.path("serviceAccountClientLink").isNull()
        || !current.path("roles").isEmpty()
        || current.path("groups").size() != 1
        || !pending.getId().equals(current.path("groups").get(0).asText())
        || !LifecycleAuthorization.equal(
            row.profileFingerprint, auth.mac("pending-profile", current))) conflict();
    var user = session.users().getUserById(realm, row.accountId);
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) {
      cache.evict(realm, user);
      user = session.users().getUserById(realm, row.accountId);
    }
    if (user == null) conflict();
    return new PendingAccount(user, current);
  }

  static JsonNode lockedSnapshot(EntityManager em, String id) {
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

  private JsonNode receipt(AccountLifecycleAttempt row, String operation, String digest) {
    var value = JSON.createObjectNode();
    value.put("realmId", row.realmId);
    value.put("attemptId", row.attemptId);
    value.put("accountId", row.accountId);
    value.put("ownerClient", row.ownerClient);
    value.put("ownerSubject", row.ownerSubject);
    value.put("scope", row.scope);
    value.put("creationFingerprint", row.creationFingerprint);
    value.put("groupId", row.groupId);
    value.put("roleFingerprint", row.roleFingerprint);
    value.put("state", row.state);
    value.put("generation", row.generation);
    value.put("executionId", row.executionId);
    value.put("operation", operation);
    value.put("commandDigest", digest);
    return value;
  }

  private Response result(AccountLifecycleAttempt row, int status) {
    var body = JSON.createObjectNode();
    body.put("attemptId", row.attemptId);
    body.put("accountId", row.accountId);
    body.put("state", row.state);
    var execution = body.putObject("execution");
    execution.put("executionId", row.executionId);
    execution.put("generation", row.generation);
    body.put("creationProof", row.creationProof);
    body.put("recoveryReceipt", row.recoveryReceipt);
    body.put("terminalReceipt", row.terminalReceipt);
    return ok(body, status);
  }

  private JsonNode projection(PendingAccount pending) {
    var current = pending.snapshot();
    var body = JSON.createObjectNode();
    for (String field :
        List.of("id", "username", "email", "firstName", "lastName", "enabled", "emailVerified"))
      body.set(field, current.path(field));
    var attributes = current.path("attributes");
    body.set(
        "tenantId",
        attributes.path("tenantId").path(0).isMissingNode()
            ? JSON.nullNode()
            : attributes.path("tenantId").path(0));
    body.set(
        "preferredLanguage",
        attributes.path("locale").path(0).isMissingNode()
            ? JSON.nullNode()
            : attributes.path("locale").path(0));
    // Integrity proves no direct grant and exactly the locked, privilege-empty pending group.
    body.putArray("effectiveRoles");
    boolean passwordChange = false;
    for (var action : current.path("requiredActions"))
      if (UserModel.RequiredAction.UPDATE_PASSWORD.name().equals(action.asText()))
        passwordChange = true;
    body.put("passwordChangeRequired", passwordChange);
    return body;
  }

  private void audit(RealmModel realm, String actor, OperationType operation, String account) {
    var event = new AdminEvent();
    event.setTime(System.currentTimeMillis());
    event.setRealmId(realm.getId());
    event.setOperationType(operation);
    event.setResourceType(ResourceType.USER);
    event.setResourcePath("accounts/" + account);
    var details = new AuthDetails();
    details.setRealmId(realm.getId());
    details.setClientId(
        "ACCOUNT_CREATE".equals(actor) ? "backend-account-create" : "backend-account-admin");
    details.setUserId("ACCOUNT_CREATE".equals(actor) ? auth.creatorSubject : auth.adminSubject);
    event.setAuthDetails(details);
    if (realm.isAdminEventsEnabled())
      session.getProvider(org.keycloak.events.EventStoreProvider.class).onEvent(event, false);
  }

  private static Response ok(JsonNode body, int status) {
    return Response.status(status).entity(body).header("Cache-Control", "no-store").build();
  }

  private enum Unavailable {
    USERNAME_NOT_AVAILABLE,
    EMAIL_NOT_AVAILABLE
  }

  private static final class AvailabilityConflict extends RuntimeException {
    private final Unavailable reason;

    private AvailabilityConflict(Unavailable reason) {
      super(null, null, false, false);
      this.reason = reason;
    }
  }

  private static void conflict() {
    throw new ClientErrorException("Lifecycle state conflicts", 409);
  }

  public Object getResource() {
    return this;
  }

  public void close() {}
}
