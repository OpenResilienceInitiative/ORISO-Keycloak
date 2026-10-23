package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import java.util.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserCredentialModel;

/** Finite administration of one positively committed ordinary native profile. */
final class OrdinaryAccountOperations {
  private record Prepared(JsonNode response, JsonNode nativeState, GeneralPolicy.Profile profile,
      GeneralPolicy.Profile desired, MaintenanceLineage.Current lineage, MaintenanceReplayReach.Checked reach) {}

  static JsonNode read(KeycloakSession session, LifecycleAuthorization crypto, Map<String, Set<String>> mappings,
      GeneralPolicy policy, MaintenanceRequest request, String human) {
    return prepare(session, crypto, mappings, policy, request, human).response;
  }

  static JsonNode readCausal(KeycloakSession session, LifecycleAuthorization crypto, Map<String, Set<String>> mappings,
      GeneralPolicy policy, CausalPasswordRequest causal) {
    causal.requireLive();
    return prepare(session, crypto, mappings, policy, causal.target(), null, causal).response;
  }

  static JsonNode readAdoptedSelf(KeycloakSession session, LifecycleAuthorization crypto,
      Map<String, Set<String>> mappings, GeneralPolicy policy, MaintenanceRequest request, String human,
      String otpOperation) {
    if (!"SELF".equals(request.target().path("origin").path("kind").asText()) || request.workflow() != null) deny();
    return prepare(session, crypto, mappings, policy, request, human, null, null, otpOperation).response;
  }

  static MaintenanceReplayReach.Checked mutate(KeycloakSession session, LifecycleAuthorization crypto, Map<String, Set<String>> mappings,
      GeneralPolicy policy, MaintenanceRequest request, JsonNode body, String human) {
    var prepared = prepare(session, crypto, mappings, policy, request, human);
    if (!LifecycleAuthorization.equal(request.expectedState(), prepared.response.path("state").asText()))
      throw MaintenancePreflightRefusal.current(409,prepared.reach);
    if ("reactivate".equals(request.command())
        && (!request.change().path("expectedUsername").equals(prepared.response.path("username"))
            || !request.change().path("expectedEmail").equals(prepared.response.path("email"))))
      throw MaintenancePreflightRefusal.current(409,prepared.reach);
    var realm = session.getContext().getRealm();
    var user = session.users().getUserById(realm, request.accountId());
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) { cache.evict(realm, user); user = session.users().getUserById(realm, request.accountId()); }
    if (user == null) throw MaintenancePreflightRefusal.current(409,prepared.reach);
    if ("reactivate".equals(request.command())
        && session.getProvider(org.keycloak.policy.PasswordPolicyManagerProvider.class)
            .validate(realm, user, request.change().path("password").textValue()) != null)
      throw MaintenancePreflightRefusal.passwordPolicy(request,prepared.reach);
    // Every definite preflight check above precedes the first native write below.
    switch (request.command()) {
      case "profile", "email" -> profile(user, request.change());
      case "ordinary-profile", "profile-transition" -> {
        var desired = session.groups().getGroupById(realm, prepared.desired.groupId);
        var current = session.groups().getGroupById(realm, prepared.profile.groupId);
        if (desired == null || current == null) throw new IllegalStateException("Profile changed during effect");
        MaintenanceLineage.append(session, crypto, request, body, prepared.lineage,
            prepared.desired.id, prepared.desired.version, request.target().path("tenantId"), prepared.desired.snapshot);
        if (!prepared.desired.groupId.equals(prepared.profile.groupId)) { user.leaveGroup(current); user.joinGroup(desired); }
        if (request.change().has("profile")) profile(user, request.change().path("profile"));
      }
      case "deactivate" -> user.setEnabled(false);
      case "reactivate" -> {
        user.setEnabled(false);
        if (!user.credentialManager().updateCredential(UserCredentialModel.password(request.change().path("password").textValue())))
          throw new IllegalStateException("Password effect did not complete");
        user.removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        session.users().setNotBeforeForUser(realm, user, org.keycloak.common.util.Time.currentTime());
        var nativeSessions = session.sessions().getUserSessionsStream(realm, user).toList();
        for (var nativeSession : nativeSessions)
          org.keycloak.services.managers.AuthenticationManager.backchannelLogout(session, realm, nativeSession,
              session.getContext().getUri(), session.getContext().getConnection(), session.getContext().getRequestHeaders(), true);
        if (session.sessions().getUserSessionsStream(realm, user).findAny().isPresent())
          throw new IllegalStateException("Session revocation did not complete");
        user.setEnabled(true);
      }
      default -> deny();
    }
    var em = CurrentNativeHumanIdentity.entityManager(session); em.flush();
    var fresh = AccountLifecycleResource.lockedSnapshot(em, request.accountId());
    if (Set.of("ordinary-profile","profile-transition").contains(request.command())
        && (fresh.path("groups").size() != 1 || !prepared.desired.groupId.equals(fresh.path("groups").path(0).asText())
            || !fresh.path("roles").isEmpty())) throw new IllegalStateException("Profile membership effect did not complete");
    if (Set.of("deactivate", "reactivate").contains(request.command())
        && fresh.path("enabled").asBoolean() != "reactivate".equals(request.command()))
      throw new IllegalStateException("Status effect did not complete");
    var changed = "ordinary-profile".equals(request.command()) ? request.change().path("profile") : request.change();
    if (Set.of("profile", "email", "ordinary-profile").contains(request.command()) && changed.isObject())
      for (var fields = changed.fields(); fields.hasNext();) {
        var field = fields.next();
        if (!field.getValue().equals(fresh.path(field.getKey()))) throw new IllegalStateException("Profile effect did not complete");
      }
    return prepared.reach;
  }

  private static Prepared prepare(KeycloakSession session, LifecycleAuthorization crypto,
      Map<String, Set<String>> mappings, GeneralPolicy policy, MaintenanceRequest request, String human) {
    return prepare(session, crypto, mappings, policy, request, human, null);
  }

  private static Prepared prepare(KeycloakSession session, LifecycleAuthorization crypto,
      Map<String, Set<String>> mappings, GeneralPolicy policy, MaintenanceRequest request, String human,
      CausalPasswordRequest causal) {
    return prepare(session,crypto,mappings,policy,request,human,causal,null);
  }

  static MaintenanceReplayReach.Checked checkedReach(KeycloakSession session,LifecycleAuthorization crypto,
      Map<String,Set<String>> mappings,GeneralPolicy policy,MaintenanceRequest request,String human) {
    return prepare(session,crypto,mappings,policy,request,human).reach;
  }

  static void replayReach(KeycloakSession session,LifecycleAuthorization crypto,Map<String,Set<String>> mappings,
      GeneralPolicy policy,MaintenanceRequest request,String human,Set<String> operations) {
    prepare(session,crypto,mappings,policy,request,human,null,operations);
  }

  record DeletedProfile(GeneralPolicy.Profile profile,JsonNode tenant) {}
  /** Immutable provenance and lineage only; caller must first verify the exact owned deletion tombstone. */
  static DeletedProfile deletedProfile(KeycloakSession session,LifecycleAuthorization crypto,Map<String,Set<String>> mappings,
      GeneralPolicy policy,String account) {
    var em=CurrentNativeHumanIdentity.entityManager(session);var realm=session.getContext().getRealm();
    var rows=em.createQuery("select a from AccountLifecycleAttempt a where a.realmId=:realm and a.accountId=:account",AccountLifecycleAttempt.class)
        .setParameter("realm",realm.getId()).setParameter("account",account).setLockMode(LockModeType.PESSIMISTIC_WRITE).setMaxResults(2).getResultList();
    GeneralPolicy.Profile baseline;JsonNode tenant;String provenance;
    if(rows.isEmpty()){
      var adoption=policy.adoptedAccounts.get(account);if(adoption==null)deny();
      baseline=policy.profile(adoption.profileId(),adoption.profileVersion());
      var anchor=MaintenanceAdoption.historical(session,crypto,account,"ORDINARY",baseline.id,baseline.version,baseline.snapshot);
      tenant=anchor.tenant();provenance=anchor.provenance();
    }else{
      if(rows.size()!=1)deny();var row=rows.get(0);em.refresh(row);
      if(!"COMMITTED".equals(row.state)||!"commit".equals(row.terminalOperation)||!"backend-account-create".equals(row.ownerClient)
          ||!crypto.creatorSubject.equals(row.ownerSubject)||row.creationProof==null||row.terminalReceipt==null||row.terminalDigest==null)deny();
      var scope=parse(row.scope);LifecycleGroups.scope(scope);var roles=mappings.get(scope.path("initialGroup").asText());
      if(roles==null||!LifecycleAuthorization.equal(row.roleFingerprint,crypto.mac("initial-roles",JSON.valueToTree(new TreeSet<>(roles)))))deny();
      baseline=policy.profileForGroup(row.groupId,roles);verifyCommitted(crypto,realm.getName(),row,scope);
      var origin=JSON.createObjectNode();origin.put("attempt",row.id);origin.put("creationProof",row.creationProof);
      origin.put("terminalReceipt",row.terminalReceipt);origin.set("scope",scope);
      provenance=crypto.mac("maintenance-provenance/v1",origin);tenant=scope.path("tenantId");
    }
    var lineage=MaintenanceLineage.resolve(session,crypto,account,provenance,"ORDINARY",baseline.id,baseline.version,tenant,baseline.snapshot);
    var current=policy.profile(lineage.profileId(),lineage.profileVersion());
    if(!canonical(current.snapshot).equals(canonical(lineage.nativeProfile()))||!current.realmRoles.equals(mappings.get(current.path)))deny();
    policy.validateProfile(session,current);LifecycleGroups.group(session,realm,current.path,current.realmRoles);
    return new DeletedProfile(current,lineage.tenant());
  }

  private static Prepared prepare(KeycloakSession session,LifecycleAuthorization crypto,
      Map<String,Set<String>> mappings,GeneralPolicy policy,MaintenanceRequest request,String human,
      CausalPasswordRequest causal,Set<String> replayOperations) {
    return prepare(session,crypto,mappings,policy,request,human,causal,replayOperations,null);
  }

  private static Prepared prepare(KeycloakSession session,LifecycleAuthorization crypto,
      Map<String,Set<String>> mappings,GeneralPolicy policy,MaintenanceRequest request,String human,
      CausalPasswordRequest causal,Set<String> replayOperations,String otpOperation) {
    boolean self = "SELF".equals(request.target().path("origin").path("kind").asText()) && request.workflow() == null;
    if (policy == null || !(self ? Set.of("read", "profile", "email", "locale", "password", "self-password")
        : Set.of("read", "profile", "email", "ordinary-profile", "profile-transition", "deactivate", "reactivate"))
        .contains(request.command())) deny();
    if (otpOperation != null && (!self || !"read".equals(request.command())
        || !Set.of("otp.read", "otp.app-setup", "otp.delete", "otp.email-start", "otp.email-finish").contains(otpOperation))) deny();
    var realm = session.getContext().getRealm(); var em = CurrentNativeHumanIdentity.entityManager(session);
    var lockedRealm = em.find(org.keycloak.models.jpa.entities.RealmEntity.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
    if (lockedRealm == null) deny(); em.refresh(lockedRealm);
    if (realm.getComponentsStream(realm.getId(), "org.keycloak.storage.UserStorageProvider").findAny().isPresent()) deny();
    if (!em.createNativeQuery("select ID from ORISO_ACCOUNT_MAINTENANCE_OP where REALM_ID=:realm"
        + " and ACCOUNT_ID=:account and COMMAND='delete' for update")
        .setParameter("realm", realm.getId()).setParameter("account", request.accountId()).getResultList().isEmpty()) deny();
    var rows = em.createQuery("select a from AccountLifecycleAttempt a where a.realmId=:realm and a.accountId=:account",
        AccountLifecycleAttempt.class).setParameter("realm", realm.getId()).setParameter("account", request.accountId())
        .setLockMode(LockModeType.PESSIMISTIC_WRITE).setMaxResults(2).getResultList();
    GeneralPolicy.Profile baseline; JsonNode originalTenant; String provenance; String stateProvenance;
    MaintenanceAdoption.Baseline adoptionBaseline=null;
    if(rows.isEmpty()) {
      // Adoption proves the incarnation; current human or separate workflow checks supply authority.
      if(!self && !"HUMAN_ADMIN".equals(request.target().path("origin").path("kind").asText())
          && (request.workflow()==null||!"INACTIVITY".equals(request.workflow().path("kind").asText())))deny();
      var adoption=policy.adoptedAccounts.get(request.accountId());if(adoption==null)deny();
      baseline=policy.profile(adoption.profileId(),adoption.profileVersion());
      adoptionBaseline=MaintenanceAdoption.prepare(session,crypto,request.accountId(),"ORDINARY",baseline.id,baseline.version,
          baseline.snapshot,request.target().path("tenantId"));
      originalTenant=adoptionBaseline.tenant();provenance=adoptionBaseline.provenance();stateProvenance=provenance;
    } else {
      if(rows.size()!=1)deny();var row=rows.get(0);em.refresh(row);
      if (!"COMMITTED".equals(row.state) || !"commit".equals(row.terminalOperation)
          || !"backend-account-create".equals(row.ownerClient) || !crypto.creatorSubject.equals(row.ownerSubject)
          || row.creationProof == null || row.terminalReceipt == null || row.terminalDigest == null) deny();
      var scope = parse(row.scope); LifecycleGroups.scope(scope);
      var originalRoles = mappings.get(scope.path("initialGroup").asText());
      if (originalRoles == null || !LifecycleAuthorization.equal(row.roleFingerprint,
          crypto.mac("initial-roles", JSON.valueToTree(new TreeSet<>(originalRoles))))) deny();
      baseline = policy.profileForGroup(row.groupId, originalRoles);
      verifyCommitted(crypto, realm.getName(), row, scope);
      var origin = JSON.createObjectNode(); origin.put("attempt", row.id); origin.put("creationProof", row.creationProof);
      origin.put("terminalReceipt", row.terminalReceipt); origin.set("scope", scope);
      provenance=crypto.mac("maintenance-provenance/v1",origin);originalTenant=scope.path("tenantId");stateProvenance=row.id;
    }
    var lineage = MaintenanceLineage.resolve(session, crypto, request.accountId(), provenance,
        "ORDINARY", baseline.id, baseline.version, originalTenant, baseline.snapshot);
    var profile = policy.profile(lineage.profileId(), lineage.profileVersion());
    boolean transition="profile-transition".equals(request.command());
    boolean imported=request.workflow()!=null&&"IMPORT".equals(request.workflow().path("kind").asText());
    if(transition&&!request.change().has("group"))deny();
    var desired = Set.of("ordinary-profile","profile-transition").contains(request.command())
        ? policy.desiredProfile(request.change().path("group").asText()) : profile;
    if (!transition&&!imported&&!Objects.equals(LifecycleGroups.allowedKind(profile.realmRoles), LifecycleGroups.allowedKind(desired.realmRoles))
        ||!canonical(profile.snapshot).equals(canonical(lineage.nativeProfile()))
        ||!profile.realmRoles.equals(mappings.get(profile.path))||!desired.realmRoles.equals(mappings.get(desired.path))) deny();
    LifecycleGroups.group(session,realm,profile.path,profile.realmRoles);
    LifecycleGroups.group(session,realm,desired.path,desired.realmRoles);
    if (self) {
      policy.requireSelfRead(session, request, human);
      if (otpOperation == null) policy.requireSelf(session, request, human);
      else switch (otpOperation) {
        case "otp.read" -> policy.requireSelfOtpRead(session, request, human);
        case "otp.app-setup" -> policy.requireSelfOtpAppSetup(session, request, human);
        case "otp.delete" -> policy.requireSelfOtpDelete(session, request, human);
        case "otp.email-start" -> policy.requireSelfOtpEmailStart(session, request, human);
        case "otp.email-finish" -> policy.requireSelfOtpEmailFinish(session, request, human);
        default -> deny();
      }
    } else if (causal != null) causal.requireProfile("ORDINARY", profile.id, profile.version);
    else if(request.workflow()!=null && "INACTIVITY".equals(request.target().path("origin").path("kind").asText())) {
      if(human!=null)deny();policy.workflowOperations.require(profile.id,"account."+request.command());
    } else if(imported&&"IMPORT".equals(request.target().path("origin").path("kind").asText())){
      if(human!=null)deny();
      for(var id:new HashSet<>(List.of(profile.id,desired.id)))policy.workflowOperations.require("IMPORT",id,"account."+request.command());
    } else {
      var source = HumanAdminSource.require(session, crypto, request, human);
      if(request.workflow()!=null&&"INACTIVITY".equals(request.workflow().path("kind").asText())&&!"PLATFORM".equals(source.authority()))deny();
      for(String operation:replayOperations==null?MaintenanceReplayReach.operations(request):replayOperations)
        policy.requireAdmin(source,request,operation,profile,desired);
    }
    var reach=self ? null : MaintenanceReplayReach.ordinary(request,profile,desired,
        replayOperations==null?MaintenanceReplayReach.operations(request):replayOperations);
    // All failures below are definite target/CAS preflight refusals for the actual authorized source.
    try {
      if (!realm.getId().equals(policy.nativePolicy.realmId) || !lineage.tenant().equals(request.target().path("tenantId"))
          || policy.nativePolicy.subjects.contains(request.accountId())) deny();
      policy.validateProfile(session, profile); policy.validateProfile(session, desired);
      var current = AccountLifecycleResource.lockedSnapshot(em, request.accountId());
      if (!realm.getId().equals(current.path("realmId").asText()) || !current.path("serviceAccountClientLink").isNull()
          || !current.path("federationLink").isNull() || !current.path("roles").isEmpty()
          || current.path("groups").size() != 1 || !profile.groupId.equals(current.path("groups").path(0).asText())) deny();
      var tenants = current.path("attributes").path("tenantId");
      JsonNode actualTenant = tenants.isMissingNode() || tenants.isEmpty() ? JSON.nullNode() : tenants.path(0);
      if (!tenants.isMissingNode() && tenants.size() != 1 || !actualTenant.equals(lineage.tenant())
          || actualTenant.isNull() && !profile.allowUnassignedTenant) deny();
      if (causal != null) causal.requireNativeBinding(crypto, current);
      if(imported)MaintenanceRoleChange.requireImportProfile(profile.snapshot);
      var roleChange=MaintenanceRoleChange.capsule(request);
      if(roleChange!=null)MaintenanceRoleChange.require(roleChange,"ORDINARY",profile.snapshot,desired.snapshot);
      if(adoptionBaseline!=null)adoptionBaseline.checked(session);
      var state = JSON.createObjectNode(); state.set("account", current); state.put("realmId", realm.getId());
      state.put("provenance", stateProvenance); state.put("groupId", profile.groupId);
      state.set("effectiveRoles", JSON.valueToTree(new TreeSet<>(profile.realmRoles)));
      if (lineage.digest() != null) state.put("lineageDigest", lineage.digest());
      var result = JSON.createObjectNode();
      for (String field : List.of("id", "username", "email", "firstName", "lastName", "enabled", "emailVerified"))
        result.set(field, current.path(field));
      result.set("tenantId", actualTenant);
      var locale = current.path("attributes").path("locale");
      if (!locale.isMissingNode() && locale.size() != 1) deny();
      result.set("preferredLanguage", locale.isMissingNode() ? JSON.nullNode() : locale.path(0));
      result.set("effectiveRoles", JSON.valueToTree(new TreeSet<>(profile.realmRoles)));
      boolean changeRequired = false;
      for (var action : current.path("requiredActions")) if ("UPDATE_PASSWORD".equals(action.asText())) changeRequired = true;
      result.put("passwordChangeRequired", changeRequired); result.put("state", crypto.mac("maintenance-state", state));
      if ("TWO_FACTOR_STATUS_V1".equals(request.include())) result.set("twoFactor", NativeOtpStatus.read(current));
      return new Prepared(result, current, profile, desired, lineage, reach);
    } catch (jakarta.ws.rs.WebApplicationException refused) {
      int status = refused.getResponse().getStatus();
      if (causal == null && (status == 403 || status == 409)) throw MaintenancePreflightRefusal.current(status,reach);
      throw refused;
    }
  }

  static void verifyCommitted(LifecycleAuthorization crypto, String realmName,
      AccountLifecycleAttempt row, JsonNode scope) {
    var creation = JSON.createObjectNode(); creation.put("v", 1); creation.put("realmName", realmName);
    creation.put("realmId", row.realmId); creation.put("attemptId", row.attemptId); creation.put("accountId", row.accountId);
    creation.put("ownerClient", row.ownerClient); creation.put("ownerSubject", row.ownerSubject); creation.set("scope", scope);
    creation.put("initialGroupId", row.groupId); creation.put("initialRoleFingerprint", row.roleFingerprint);
    creation.put("creationFingerprint", row.creationFingerprint);
    var terminal = JSON.createObjectNode(); terminal.put("realmId", row.realmId); terminal.put("attemptId", row.attemptId);
    terminal.put("accountId", row.accountId); terminal.put("ownerClient", row.ownerClient); terminal.put("ownerSubject", row.ownerSubject);
    terminal.put("scope", row.scope); terminal.put("creationFingerprint", row.creationFingerprint); terminal.put("groupId", row.groupId);
    terminal.put("roleFingerprint", row.roleFingerprint); terminal.put("state", row.state); terminal.put("generation", row.generation);
    terminal.put("executionId", row.executionId); terminal.put("operation", row.terminalOperation); terminal.put("commandDigest", row.terminalDigest);
    if (!LifecycleAuthorization.equal(crypto.creationReceipt(creation), row.creationProof)
        || !LifecycleAuthorization.equal(crypto.receipt("terminal-receipt", terminal), row.terminalReceipt)) deny();
  }
  private static void profile(UserModel user, JsonNode change) {
    if (change.has("firstName")) { user.setFirstName(change.path("firstName").textValue()); user.setLastName(change.path("lastName").textValue()); }
    if (!Objects.equals(user.getEmail(), change.path("email").textValue())) {
      user.setEmail(change.path("email").textValue()); user.setEmailVerified(false);
    }
  }
  private OrdinaryAccountOperations() {}
}
