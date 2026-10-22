package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import java.util.Set;
import java.util.TreeSet;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.RealmEntity;

/** Separate finite operation grants over checked committed protected provenance; never approval authority. */
final class ProtectedAccountOperations {
  private static final String MARKER = "PROTECTED_ACCOUNT_OPERATIONS_V1";

  static boolean selected(JsonNode target) {
    return Set.of("SELF", "HUMAN_ADMIN").contains(target.path("origin").path("kind").asText())
        && MARKER.equals(target.path("origin").path("humanAuthority").asText());
  }

  static JsonNode readSelfOtp(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String fullHumanHeader) {
    return readCurrent(session, crypto, request, fullHumanHeader, "otp.read");
  }

  static JsonNode readSelfAppSetup(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String fullHumanHeader) {
    return readCurrent(session, crypto, request, fullHumanHeader, "otp.app-setup");
  }

  static JsonNode readAccount(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String fullHumanHeader) {
    return readCurrent(session, crypto, request, fullHumanHeader, "account.read");
  }

  static JsonNode readCausal(KeycloakSession session, LifecycleAuthorization crypto, CausalPasswordRequest causal) {
    causal.requireLive();
    return readChecked(session, crypto, causal.target(), null, "account.password-reset.read", causal).current();
  }

  static boolean protectedTarget(KeycloakSession session, MaintenanceRequest request) {
    var em = CurrentNativeHumanIdentity.entityManager(session); var realm = session.getContext().getRealm();
    var locked = em.find(RealmEntity.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
    if (locked == null) deny(); em.refresh(locked);
    var scopes = em.createQuery("select a.scope from AccountLifecycleAttempt a where a.realmId=:realm and a.accountId=:account", String.class)
        .setParameter("realm", realm.getId()).setParameter("account", request.accountId()).setMaxResults(2).getResultList();
    if (scopes.size() > 1) deny();
    if (scopes.size() == 1) return parse(scopes.get(0)).has("approvalBinding");
    if (!ProtectedInvitationFactory.checkedBootstrapConfiguration(session).adoptedAccounts.containsKey(request.accountId())) deny();
    return true;
  }

  record CheckedCurrent(JsonNode current, long humanValidUntil, MaintenanceLineage.Current lineage, ProtectedInvitationConfiguration.Profile profile) {}

  static JsonNode readSelfOperation(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String humanHeader, String operation) {
    if (!"SELF".equals(request.target().path("origin").path("kind").asText())
        || !Set.of("otp.app-setup", "otp.delete", "otp.email-finish", "otp.email-start").contains(operation)) deny();
    return readCurrent(session, crypto, request, humanHeader, operation);
  }

  static CheckedCurrent emailStart(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String humanHeader) {
    if (!"SELF".equals(request.target().path("origin").path("kind").asText())) deny();
    return readChecked(session, crypto, request, humanHeader, "otp.email-start");
  }

  static JsonNode readCurrentOperation(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String humanHeader) {
    return readCurrent(session, crypto, request, humanHeader, "account." + request.command());
  }

  static void mutate(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, JsonNode body, String humanHeader) {
    if (!"HUMAN_ADMIN".equals(request.target().path("origin").path("kind").asText())
        || !Set.of("profile", "email", "reassign-tenant").contains(request.command())) deny();
    var checked=readChecked(session, crypto, request, humanHeader, "account." + request.command());
    var current = checked.current();
    if (!LifecycleAuthorization.equal(request.expectedState(), current.path("state").asText()))
      throw MaintenancePreflightRefusal.current(409);
    var realm = session.getContext().getRealm();
    var user = session.users().getUserById(realm, request.accountId());
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) { cache.evict(realm, user); user = session.users().getUserById(realm, request.accountId()); }
    if (user == null) throw MaintenancePreflightRefusal.current(409);
    if("reassign-tenant".equals(request.command())) {
      if(body==null||!"TENANT_ADMIN".equals(checked.profile().kind()))deny();
      MaintenanceLineage.append(session,crypto,request,body,checked.lineage(),checked.profile().id(),checked.profile().version(),
          request.change().path("tenantId"),checked.profile().snapshot());
      user.setSingleAttribute("tenantId",request.change().path("tenantId").asText());
      var em=CurrentNativeHumanIdentity.entityManager(session);em.flush();var fresh=AccountLifecycleResource.lockedSnapshot(em,request.accountId());
      if(fresh.path("attributes").path("tenantId").size()!=1||!request.change().path("tenantId").equals(fresh.path("attributes").path("tenantId").path(0))
        throw new IllegalStateException("Native tenant effect did not complete");
      return;
    }
    if ("profile".equals(request.command())) {
      user.setFirstName(request.change().path("firstName").textValue());
      user.setLastName(request.change().path("lastName").textValue());
    }
    if (!request.change().path("email").equals(current.path("email"))) {
      user.setEmail(request.change().path("email").textValue());
      user.setEmailVerified(false);
    }
    var em = CurrentNativeHumanIdentity.entityManager(session); em.flush();
    var fresh = AccountLifecycleResource.lockedSnapshot(em, request.accountId());
    for (var fields = request.change().fields(); fields.hasNext();) {
      var field = fields.next(); if (!field.getValue().equals(fresh.path(field.getKey())))
        throw new jakarta.ws.rs.ClientErrorException("Current account state conflicts", 409);
    }
  }

  private static JsonNode readCurrent(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String fullHumanHeader, String operation) {
    return readChecked(session, crypto, request, fullHumanHeader, operation).current();
  }

  private static CheckedCurrent readChecked(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String fullHumanHeader, String operation) {
    return readChecked(session, crypto, request, fullHumanHeader, operation, null);
  }

  private static CheckedCurrent readChecked(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String fullHumanHeader, String operation, CausalPasswordRequest causal) {
    boolean inactivity=request.workflow()!=null;
    boolean scheduled=inactivity&&"INACTIVITY".equals(request.target().path("origin").path("kind").asText());
    if(causal==null && !inactivity && (!selected(request.target())||!Set.of("read","profile","email","reassign-tenant").contains(request.command())
        ||!Set.of("otp.read","account.read","account.profile","account.email","account.reassign-tenant","otp.app-setup",
            "otp.delete","otp.email-finish","otp.email-start").contains(operation)))deny();
    if(inactivity&&(!Set.of("read","deactivate","reactivate").contains(request.command())||!("account."+request.command()).equals(operation)))deny();
    boolean needsHuman=causal==null&&!scheduled;
    if(needsHuman && (fullHumanHeader==null||fullHumanHeader.length()>32775||!fullHumanHeader.regionMatches(true,0,"Bearer ",0,7)))
      throw new jakarta.ws.rs.NotAuthorizedException("Bearer");
    if(!needsHuman&&fullHumanHeader!=null)deny();
    String rawHuman=needsHuman?fullHumanHeader.substring(7):null;
    var config = ProtectedInvitationFactory.checkedBootstrapConfiguration(session);
    // This transient authentication supplies a locator only. Fresh operation authority is checked
    // after realm and provenance locks through the shared native current-human implementation.
    var authenticated = needsHuman ? NativeHumanBearer.require(session, rawHuman) : null;
    var realm = session.getContext().getRealm();
    if (!config.realmId.equals(realm.getId()) || !config.realmName.equals(realm.getName())
        || realm.getComponentsStream(realm.getId(), "org.keycloak.storage.UserStorageProvider").findAny().isPresent()) deny();
    var em = CurrentNativeHumanIdentity.entityManager(session);
    var lockedRealm = em.find(RealmEntity.class, config.realmId, LockModeType.PESSIMISTIC_WRITE);
    if (lockedRealm == null) deny();
    em.refresh(lockedRealm);
    // A non-locking exact-account projection is only a locator. It grants no authority; the
    // approval and attempt are then locked in protocol order and every immutable value checked.
    var locators = em.createQuery("select a.id, a.scope, a.attemptId from AccountLifecycleAttempt a"
        + " where a.realmId=:realm and a.accountId=:account", Object[].class)
        .setParameter("realm", config.realmId).setParameter("account", request.accountId())
        .setMaxResults(2).getResultList();
    if (locators.size() > 1) deny();
    ProtectedInvitationApproval approval = null;
    AccountLifecycleAttempt attempt = null;
    ProtectedInvitationConfiguration.Profile profile;
    String provenance;
    long tenant;
    MaintenanceAdoption.Baseline adoptionBaseline=null;
    var delegation = new ProtectedPeerDelegation(session, config, crypto);
    if (locators.isEmpty()) {
      var adoption = config.adoptedAccounts.get(request.accountId());
      if (adoption == null) deny();
      profile = config.profiles.get(adoption.profileId());
      if (profile == null || profile.version() != adoption.profileVersion()) deny();
      String requestedTenant = request.target().path("tenantId").asText();
      if (!requestedTenant.matches("0|[1-9][0-9]{0,18}")) deny();
      try { tenant = Long.parseLong(requestedTenant); }
      catch (NumberFormatException invalid) { deny(); return null; }
      if ("PLATFORM_ADMIN".equals(profile.kind()) ? tenant != 0 : tenant <= 0) deny();
      adoptionBaseline=MaintenanceAdoption.prepare(session,crypto,request.accountId(),"PROTECTED",profile.id(),profile.version(),
          profile.snapshot(),request.target().path("tenantId"));
      tenant=Long.parseLong(adoptionBaseline.tenant().asText());
      provenance=adoptionBaseline.provenance();
    } else {
      var locator = locators.get(0);
      var scope = parse((String) locator[1]);
      if (!scope.path("approvalBinding").isObject()) deny();
      String approvalId = uuid(text(scope.path("approvalBinding"), "approvalId", 36, false));
      approval = em.find(ProtectedInvitationApproval.class,
          ProtectedInvitationResource.key(config.realmId, approvalId), LockModeType.PESSIMISTIC_WRITE);
      if (approval == null) deny(); em.refresh(approval);
      attempt = em.find(AccountLifecycleAttempt.class, locator[0], LockModeType.PESSIMISTIC_WRITE);
      if (attempt == null) deny(); em.refresh(attempt);
      if (!request.accountId().equals(attempt.accountId) || !locator[2].equals(attempt.attemptId)
          || !locator[1].equals(attempt.scope)) deny();
      var frozen = parse(approval.scope).path("profile");
      profile = config.profiles.get(text(frozen, "id", 255, false));
      if (profile == null || !Set.of("TENANT_ADMIN", "PLATFORM_ADMIN").contains(profile.kind())
          || !canonical(profile.snapshot()).equals(canonical(frozen))) deny();
      tenant = delegation.committedOperationTarget(approval, attempt, profile);
      var adoption = config.adoptedAccounts.get(request.accountId());
      if (adoption != null && (!profile.id().equals(adoption.profileId())
          || profile.version() != adoption.profileVersion())) deny();
      provenance = attempt.id;
    }
    var lineage=MaintenanceLineage.resolve(session,crypto,request.accountId(),provenance,"PROTECTED",profile.id(),profile.version(),
        JSON.valueToTree(Long.toString(tenant)),profile.snapshot());
    if(!profile.id().equals(lineage.profileId())||profile.version()!=lineage.profileVersion()
        ||!canonical(profile.snapshot()).equals(canonical(lineage.nativeProfile())))deny();
    try{tenant=Long.parseLong(lineage.tenant().asText());}catch(NumberFormatException malformed){deny();return null;}
    if(("PLATFORM_ADMIN".equals(profile.kind())?tenant!=0:tenant<=0)||!Long.toString(tenant).equals(request.target().path("tenantId").asText()))deny();
    long validUntil;
    if (causal != null) {
      causal.requireProfile("PROTECTED", profile.id(), profile.version()); validUntil = 0;
    } else if(scheduled){
      config.workflowOperations.require(profile.id(),operation);validUntil=0;
    } else if (approval != null && "PLATFORM_ADMIN".equals(profile.kind())
        && "SELF".equals(request.target().path("origin").path("kind").asText())) {
      validUntil = requireCommittedRecipientSelf(session, config, approval, profile, request, rawHuman, operation, tenant);
    } else {
      var resolved = delegation.resolve(authenticated, em);
      var human = delegation.require(resolved, rawHuman);
      if((inactivity||"reassign-tenant".equals(request.command()))
          &&(!"PLATFORM".equals(resolved.binding().authority())||resolved.sourceProfile()!=null||human.tenantId()!=0))deny();
      var origin = request.target().path("origin");
      if ("SELF".equals(origin.path("kind").asText()) && !request.accountId().equals(human.subject())
          || !human.subject().equals(origin.path("humanSubject").asText())
          || !human.issuer().equals(origin.path("humanIssuer").asText())
          || !human.clientId().equals(origin.path("humanClient").asText())) deny();
      var grants = config.bindingAccountOperations.get(human.subject());
      if (resolved.sourceProfile() != null) {
        var policies = config.peerPolicies.values().stream().filter(policy ->
            policy.sourceProfileId().equals(resolved.sourceProfile().id())
                && policy.sourceProfileVersion() == resolved.sourceProfile().version()).toList();
        if (policies.size() != 1) deny();
        grants = config.peerAccountOperations.get(policies.get(0).id());
      }
      if (grants == null || grants.stream().noneMatch(grant ->
          grant.authority().equals(resolved.binding().authority()) && grant.profiles().contains(profile.id())
              && grant.operations().contains(operation)
              && (!grant.selfOnly() || human.subject().equals(request.accountId()))
              && (grant.targetSubjects().isEmpty() || grant.targetSubjects().contains(request.accountId())))) deny();
      if ("TENANT_PEER".equals(resolved.binding().authority()) && human.tenantId() != tenant
          || "PLATFORM".equals(resolved.binding().authority()) && human.tenantId() != 0) deny();
      validUntil = human.validatedJwtExpiresAt();
    }
    try {
    config.validateProfile(session, profile);
    var current = AccountLifecycleResource.lockedSnapshot(em, request.accountId());
    var groups = new TreeSet<String>(); current.path("groups").forEach(value -> groups.add(value.asText()));
    var tenantValues = current.path("attributes").path("tenantId");
    if (!config.realmId.equals(current.path("realmId").asText()) || !inactivity && !current.path("enabled").asBoolean()
        || !current.path("serviceAccountClientLink").isNull() || !current.path("federationLink").isNull()
        || !current.path("roles").isEmpty() || !groups.equals(Set.of(profile.groupId()))
        || tenantValues.size() != 1 || !Long.toString(tenant).equals(tenantValues.path(0).asText())) deny();
    for (var technical : config.installation.path("technicalSubjects"))
      if (request.accountId().equals(technical.asText())) deny();
    if (causal != null) causal.requireNativeBinding(crypto, current);
    if(adoptionBaseline!=null)adoptionBaseline.checked(session);
    var state = JSON.createObjectNode();
    state.put("realmId", config.realmId); state.set("account", current);
    state.put("provenance", provenance); state.set("profile", profile.snapshot());
    if(lineage.digest()!=null)state.put("lineageDigest",lineage.digest());
    var result = JSON.createObjectNode();
    for (String field : java.util.List.of("id", "username", "email", "firstName", "lastName", "enabled", "emailVerified"))
      result.set(field, current.path(field));
    result.put("tenantId", Long.toString(tenant));
    var locales = current.path("attributes").path("locale");
    if (!locales.isMissingNode() && locales.size() != 1) deny();
    result.set("preferredLanguage", locales.isMissingNode() ? JSON.nullNode() : locales.path(0));
    result.set("effectiveRoles", JSON.valueToTree(new TreeSet<>(profile.realmRoles())));
    boolean passwordChange = false;
    for (var action : current.path("requiredActions"))
      if (org.keycloak.models.UserModel.RequiredAction.UPDATE_PASSWORD.name().equals(action.asText())) passwordChange = true;
    result.put("passwordChangeRequired", passwordChange);
    result.put("state", crypto.mac("maintenance-state", state));
    if ("TWO_FACTOR_STATUS_V1".equals(request.include())) result.set("twoFactor", NativeOtpStatus.read(current));
    return new CheckedCurrent(result, validUntil, lineage, profile);
    } catch (jakarta.ws.rs.WebApplicationException refused) {
      int status = refused.getResponse().getStatus();
      if ((inactivity||"HUMAN_ADMIN".equals(request.target().path("origin").path("kind").asText()))
          && (status == 403 || status == 409)) throw MaintenancePreflightRefusal.current(status);
      throw refused;
    }
  }

  private static long requireCommittedRecipientSelf(KeycloakSession session,
      ProtectedInvitationConfiguration config, ProtectedInvitationApproval approval,
      ProtectedInvitationConfiguration.Profile profile, MaintenanceRequest request,
      String rawHuman, String operation, long tenant) {
    var source = config.bindings.get(approval.issuerSubject);
    var issued = parse(approval.approvalReceipt);
    if (source == null || !"PLATFORM".equals(source.authority()) || tenant != 0
        || source.policy().version != number(issued, "bindingVersion", true)) deny();
    var grants = config.bindingAccountOperations.get(approval.issuerSubject);
    if (grants == null || grants.stream().noneMatch(grant ->
        "PLATFORM".equals(grant.authority()) && grant.selfOnly()
            && grant.profiles().contains(profile.id()) && grant.operations().contains(operation)
            && (grant.targetSubjects().isEmpty() || grant.targetSubjects().contains(request.accountId())))) deny();
    // Reuse only source issuer/client/audience/technical constraints. Its privileged subject and
    // approval authority are never transferred to this independently committed recipient.
    var human = CurrentNativeHumanIdentity.require(session, source.policy().nativePolicy, rawHuman);
    var origin = request.target().path("origin");
    if (!request.accountId().equals(human.subject())
        || !human.subject().equals(origin.path("humanSubject").asText())
        || !human.issuer().equals(origin.path("humanIssuer").asText())
        || !human.clientId().equals(origin.path("humanClient").asText())
        || human.tenantId() == null || human.tenantId() != 0
        || !profile.realmRoles().equals(human.realmRoles())
        || !profile.clientRoles().equals(human.clientRoles())) deny();
    return human.validatedJwtExpiresAt();
  }

  private ProtectedAccountOperations() {}
}
