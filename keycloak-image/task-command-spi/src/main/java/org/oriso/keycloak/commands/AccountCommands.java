package org.oriso.keycloak.commands;

import static org.oriso.keycloak.commands.CommandValidation.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.*;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.userprofile.*;
import org.oriso.keycloak.auth.*;

final class AccountCommands {
  private final KeycloakSession session;
  private final RealmModel realm;
  private final OriginAuthorization origins;

  AccountCommands(KeycloakSession session, OriginAuthorization origins) {
    this.session = session;
    this.realm = session.getContext().getRealm();
    this.origins = origins;
  }

  private EntityManager em() {
    return session.getProvider(JpaConnectionProvider.class).getEntityManager();
  }

  Response create(String attemptId, JsonNode body, String encoded) {
    try {
      if (!UUID.fromString(attemptId).toString().equals(attemptId)) bad();
    } catch (IllegalArgumentException e) {
      bad();
    }
    fields(
        body,
        "username",
        "email",
        "firstName",
        "lastName",
        "preferredLanguage",
        "tenantId",
        "password",
        "passwordTemporary",
        "roles",
        "registrationKind");
    var caller = TaskIdentity.require(session, "account-provisioning", "account-provisioning");
    var grant = origins.require(encoded, caller, "account.create", attemptId, body, true);
    String username = text(body, "username", true, 255), tenant = text(body, "tenantId", false, 40);
    if (!Objects.equals(tenant, grant.tenantId())) deny();
    Set<String> roleNames = roles(body, grant);
    if ("0".equals(tenant) && roleNames.contains("tenant-admin")) deny();
    createKind(text(body, "registrationKind", true, 30), roleNames, grant);
    String digest = origins.fingerprint(body), pk = realm.getId() + ":" + attemptId;
    CreationAttempt existing = em().find(CreationAttempt.class, pk, LockModeType.PESSIMISTIC_WRITE);
    if (existing != null) {
      if (!caller.subject().equals(existing.ownerSubject)
          || !caller.clientId().equals(existing.ownerClient)) deny();
      if (!digest.equals(existing.fingerprint) || !existing.status.equals("OPEN"))
        throw new ClientErrorException("Creation attempt is terminal or different", 409);
      return response(existing, 200);
    }
    if (session.users().getUserByUsername(realm, username) != null)
      throw new ClientErrorException("Account already exists", 409);
    CreationAttempt attempt = new CreationAttempt();
    attempt.id = pk;
    attempt.realmId = realm.getId();
    attempt.attemptId = attemptId;
    attempt.ownerSubject = caller.subject();
    attempt.ownerClient = caller.clientId();
    attempt.fingerprint = digest;
    attempt.status = "OPEN";
    attempt.tenantId = tenant;
    attempt.registrationKind = body.path("registrationKind").asText();
    try {
      em().persist(attempt);
      em().flush();
      Map<String, Object> attrs = new HashMap<>();
      attrs.put("username", username);
      for (String key : List.of("email", "firstName", "lastName")) {
        String value = text(body, key, false, 255);
        if (value != null) attrs.put(key, value);
      }
      UserProfile profile =
          session.getProvider(UserProfileProvider.class).create(UserProfileContext.USER_API, attrs);
      profile.validate();
      UserModel user = profile.create();
      if ((body.path("registrationKind").asText().equals("ASKER")
              || body.path("registrationKind").asText().equals("ANONYMOUS"))
          && (user.getEmail() == null || user.getEmail().isBlank())) {
        attrs.put("email", dummyEmail(user.getId()));
        UserProfile completed =
            session
                .getProvider(UserProfileProvider.class)
                .create(UserProfileContext.USER_API, attrs, user);
        completed.validate();
        completed.update(false);
      }
      user.setEnabled(true);
      user.setEmailVerified(true);
      user.setSingleAttribute("userId", user.getId());
      String decoded = URLDecoder.decode(username, StandardCharsets.UTF_8);
      user.setSingleAttribute("username", decoded);
      user.setSingleAttribute("userName", decoded);
      if (tenant != null) user.setSingleAttribute("tenantId", tenant);
      String language = text(body, "preferredLanguage", false, 20);
      user.setSingleAttribute("locale", language == null ? "de" : language);
      String password = secret(body, "password", false);
      if (password != null) setPassword(user, password, bool(body, "passwordTemporary", false));
      for (String name : roleNames) {
        RoleModel role = realm.getRole(name);
        if (role == null || role.isComposite()) bad();
        user.grantRole(role);
      }
      attempt.accountId = user.getId();
      audit(caller, OperationType.CREATE, user.getId());
      return response(attempt, 201);
    } catch (ModelDuplicateException e) {
      session.getTransactionManager().setRollbackOnly();
      throw new ClientErrorException("Account already exists", 409);
    } catch (ValidationException | ModelException e) {
      session.getTransactionManager().setRollbackOnly();
      throw new BadRequestException("Account profile or credential validation failed");
    } catch (RuntimeException e) {
      session.getTransactionManager().setRollbackOnly();
      throw e;
    }
  }

  Response finish(String attemptId, JsonNode body, String encoded, boolean commit) {
    try {
      if (!UUID.fromString(attemptId).toString().equals(attemptId)) bad();
    } catch (IllegalArgumentException e) {
      bad();
    }
    fields(body, "accountId", "creationProof");
    var caller = TaskIdentity.require(session, "account-provisioning", "account-provisioning");
    var grant =
        origins.require(
            encoded,
            caller,
            commit ? "account.commit" : "account.compensate",
            attemptId,
            body,
            true);
    var attempt =
        em().find(
                CreationAttempt.class,
                realm.getId() + ":" + attemptId,
                LockModeType.PESSIMISTIC_WRITE);
    if (attempt == null
        || !caller.subject().equals(attempt.ownerSubject)
        || !caller.clientId().equals(attempt.ownerClient)
        || !Objects.equals(attempt.accountId, text(body, "accountId", true, 255))) deny();
    if (!Objects.equals(attempt.tenantId, grant.tenantId())
        || ("IMPORT".equals(grant.originKind()) && !"CONSULTANT".equals(attempt.registrationKind)))
      deny();
    String expected =
        origins.receipt(realm.getId(), attemptId, caller.subject(), attempt.accountId);
    if (!MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8),
        text(body, "creationProof", true, 100).getBytes(StandardCharsets.UTF_8))) deny();
    if (commit) {
      if (attempt.status.equals("COMPENSATED"))
        throw new ClientErrorException("Creation was compensated", 409);
      attempt.status = "COMMITTED";
    } else {
      if (attempt.status.equals("COMMITTED"))
        throw new ClientErrorException("Creation is committed", 409);
      if (attempt.status.equals("OPEN")) {
        UserModel user = session.users().getUserById(realm, attempt.accountId);
        if (user != null) session.users().removeUser(realm, user);
        attempt.status = "COMPENSATED";
        audit(caller, OperationType.DELETE, attempt.accountId);
      }
    }
    return Response.noContent().build();
  }

  Response read(String accountId, String encoded) {
    var caller = reader();
    var grant =
        origins.require(
            encoded,
            caller,
            "account.read",
            accountId,
            OriginAuthorization.JSON.createObjectNode(),
            caller.clientId().equals(configuredProvisioner()));
    UserModel user = session.users().getUserById(realm, accountId);
    if (user == null) throw new NotFoundException("Account not found");
    target(user, grant, realm, true);
    return Response.ok(projection(user)).header("Cache-Control", "no-store").build();
  }

  Response search(String username, String email, String encoded) {
    if ((username == null) == (email == null)) bad();
    var query = OriginAuthorization.JSON.createObjectNode();
    String value = username == null ? email : username;
    query.put(username == null ? "email" : "username", value);
    text(query, username == null ? "email" : "username", true, 255);
    var caller = reader();
    var grant =
        origins.require(
            encoded,
            caller,
            "account.search",
            value,
            query,
            caller.clientId().equals(configuredProvisioner()));
    UserModel user =
        username == null
            ? session.users().getUserByEmail(realm, email)
            : session.users().getUserByUsername(realm, username);
    if (user == null) return Response.ok(List.of()).header("Cache-Control", "no-store").build();
    target(user, grant, realm);
    return Response.ok(List.of(projection(user))).header("Cache-Control", "no-store").build();
  }

  Response profile(String accountId, JsonNode body, String encoded) {
    fields(body, "username", "email", "firstName", "lastName", "tenantId", "preferredLanguage");
    var caller = TaskIdentity.require(session, "account-maintenance", "account-maintenance");
    var grant = origins.require(encoded, caller, "account.profile", accountId, body, false);
    if (!Set.of("HUMAN_ADMIN", "SELF_SERVICE", "LIFECYCLE").contains(grant.originKind())) deny();
    UserModel user = session.users().getUserById(realm, accountId);
    if (user == null) throw new NotFoundException("Account not found");
    target(user, grant, realm, true);
    if (body.has("tenantId")
        && !Objects.equals(text(body, "tenantId", false, 40), user.getFirstAttribute("tenantId")))
      deny();
    if (grant.originKind().equals("LIFECYCLE")
        && (body.size() != 1
            || !body.has("email")
            || !dummyEmail(accountId).equals(text(body, "email", true, 255)))) deny();
    Map<String, Object> attributes = new HashMap<>(user.getAttributes());
    attributes.put("username", user.getUsername());
    attributes.put("email", user.getEmail());
    attributes.put("firstName", user.getFirstName());
    attributes.put("lastName", user.getLastName());
    for (String key : List.of("username", "email", "firstName", "lastName"))
      if (body.has(key)) attributes.put(key, text(body, key, key.equals("username"), 255));
    try {
      UserProfile profile =
          session
              .getProvider(UserProfileProvider.class)
              .create(UserProfileContext.USER_API, attributes, user);
      profile.validate();
      profile.update(false);
      if (body.has("username")) {
        String decoded = URLDecoder.decode(user.getUsername(), StandardCharsets.UTF_8);
        user.setSingleAttribute("username", decoded);
        user.setSingleAttribute("userName", decoded);
      }
      if (body.has("preferredLanguage"))
        user.setSingleAttribute("locale", text(body, "preferredLanguage", true, 20));
      audit(caller, OperationType.UPDATE, accountId);
      return Response.noContent().build();
    } catch (ModelDuplicateException e) {
      session.getTransactionManager().setRollbackOnly();
      throw new ClientErrorException("Account already exists", 409);
    } catch (ValidationException | ModelException e) {
      session.getTransactionManager().setRollbackOnly();
      throw new BadRequestException("Account profile validation failed");
    } catch (RuntimeException e) {
      session.getTransactionManager().setRollbackOnly();
      throw e;
    }
  }

  Response password(String accountId, JsonNode body, String encoded) {
    fields(body, "password", "passwordTemporary");
    var caller = TaskIdentity.require(session, "account-maintenance", "account-maintenance");
    var grant = origins.require(encoded, caller, "account.password", accountId, body, false);
    if (!Set.of("HUMAN_ADMIN", "SELF_SERVICE", "ONBOARDING", "PASSWORD_RESET")
        .contains(grant.originKind())) deny();
    UserModel user = session.users().getUserById(realm, accountId);
    if (user == null) throw new NotFoundException("Account not found");
    target(user, grant, realm, true);
    try {
      setPassword(user, secret(body, "password", true), bool(body, "passwordTemporary", false));
      audit(caller, OperationType.UPDATE, accountId);
      return Response.noContent().build();
    } catch (ModelException e) {
      session.getTransactionManager().setRollbackOnly();
      throw new BadRequestException("Password validation failed");
    } catch (RuntimeException e) {
      session.getTransactionManager().setRollbackOnly();
      throw e;
    }
  }

  Response updateRoles(String accountId, JsonNode body, String encoded) {
    fields(body, "roles");
    var caller = TaskIdentity.require(session, "account-maintenance", "account-maintenance");
    var grant = origins.require(encoded, caller, "account.roles", accountId, body, false);
    if (!Set.of("HUMAN_ADMIN", "IMPORT").contains(grant.originKind())) deny();
    UserModel user = session.users().getUserById(realm, accountId);
    if (user == null) throw new NotFoundException("Account not found");
    target(user, grant, realm);
    if ("IMPORT".equals(grant.originKind())) {
      Set<String> wanted = roles(body);
      Set<String> current = new HashSet<>();
      user.getRealmRoleMappingsStream()
          .filter(role -> HUMAN_ROLES.contains(role.getName()))
          .forEach(role -> current.add(role.getName()));
      if (!wanted.containsAll(current)) deny();
      Set<String> additions = new HashSet<>(wanted);
      additions.removeAll(current);
      if (!Set.of("consultant", "group-chat-consultant").containsAll(additions)
          || !grant.roles().containsAll(additions)) deny();
      List<RoleModel> added = new ArrayList<>();
      for (String name : additions) {
        RoleModel role = realm.getRole(name);
        if (role == null || role.isComposite()) bad();
        added.add(role);
      }
      added.forEach(user::grantRole);
      audit(caller, OperationType.UPDATE, accountId);
      return Response.noContent().build();
    }
    Set<String> wanted = roles(body, grant);
    if ("0".equals(user.getFirstAttribute("tenantId")) && wanted.contains("tenant-admin")) deny();
    List<RoleModel> models = new ArrayList<>();
    for (String name : wanted) {
      RoleModel role = realm.getRole(name);
      if (role == null || role.isComposite()) bad();
      models.add(role);
    }
    user.getRealmRoleMappingsStream()
        .filter(r -> HUMAN_ROLES.contains(r.getName()))
        .toList()
        .forEach(user::deleteRoleMapping);
    models.forEach(user::grantRole);
    audit(caller, OperationType.UPDATE, accountId);
    return Response.noContent().build();
  }

  Response lifecycle(String accountId, JsonNode body, String encoded, boolean delete) {
    fields(body);
    var caller = TaskIdentity.require(session, "account-maintenance", "account-maintenance");
    var grant =
        origins.require(
            encoded,
            caller,
            delete ? "account.delete" : "account.deactivate",
            accountId,
            body,
            false);
    if (!Set.of("HUMAN_ADMIN", "LIFECYCLE").contains(grant.originKind())) deny();
    UserModel user = session.users().getUserById(realm, accountId);
    if (user == null) {
      if (delete) return Response.noContent().build();
      throw new NotFoundException("Account not found");
    }
    target(user, grant, realm);
    if (delete) {
      session.users().removeUser(realm, user);
      audit(caller, OperationType.DELETE, accountId);
    } else {
      user.setEnabled(false);
      audit(caller, OperationType.UPDATE, accountId);
    }
    return Response.noContent().build();
  }

  private String dummyEmail(String id) {
    String suffix = System.getenv("ORISO_IDENTITY_DUMMY_EMAIL_SUFFIX");
    if (suffix == null || !suffix.matches("@[A-Za-z0-9][A-Za-z0-9.-]{1,250}"))
      throw new jakarta.ws.rs.ServiceUnavailableException(
          "Managed dummy email policy is not configured");
    return id + suffix;
  }

  private String configuredProvisioner() {
    return TaskIdentity.configured("account-provisioning");
  }

  private TaskIdentity.Caller reader() {
    return TaskIdentity.requireRead(session);
  }

  private Map<String, Object> projection(UserModel user) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("id", user.getId());
    result.put("username", user.getUsername());
    result.put("email", user.getEmail());
    result.put("firstName", user.getFirstName());
    result.put("lastName", user.getLastName());
    result.put("tenantId", user.getFirstAttribute("tenantId"));
    result.put("preferredLanguage", user.getFirstAttribute("locale"));
    result.put("enabled", user.isEnabled());
    result.put("emailVerified", user.isEmailVerified());
    result.put(
        "roles",
        user.getRealmRoleMappingsStream()
            .map(RoleModel::getName)
            .filter(HUMAN_ROLES::contains)
            .sorted()
            .toList());
    result.put(
        "passwordChangeRequired",
        user.getRequiredActionsStream()
            .anyMatch(UserModel.RequiredAction.UPDATE_PASSWORD.name()::equals));
    result.replaceAll(
        (key, value) ->
            value == null ? com.fasterxml.jackson.databind.node.NullNode.instance : value);
    return result;
  }

  private Response response(CreationAttempt attempt, int status) {
    return Response.status(status)
        .header("Cache-Control", "no-store")
        .entity(
            Map.of(
                "attemptId",
                attempt.attemptId,
                "accountId",
                attempt.accountId,
                "creationProof",
                origins.receipt(
                    realm.getId(), attempt.attemptId, attempt.ownerSubject, attempt.accountId),
                "status",
                attempt.status))
        .build();
  }

  private void setPassword(UserModel user, String password, boolean temporary) {
    if (session.getProvider(PasswordPolicyManagerProvider.class).validate(realm, user, password)
        != null) throw new BadRequestException("Password policy not met");
    if (!user.credentialManager().updateCredential(UserCredentialModel.password(password)))
      throw new BadRequestException("Credential update failed");
    if (temporary) user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
    else user.removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
  }

  private void audit(TaskIdentity.Caller caller, OperationType operation, String userId) {
    CommandAudit.record(
        session,
        caller,
        operation,
        "ORISO_ACCOUNT_COMMAND",
        "accounts/" + userId,
        Map.of("accountId", userId, "operation", operation.name()));
  }
}
