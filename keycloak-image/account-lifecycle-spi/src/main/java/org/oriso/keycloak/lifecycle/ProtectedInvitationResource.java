package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.*;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;
import org.keycloak.models.*;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.services.resource.RealmResourceProvider;

/** Human approval and designated-owner lifecycle, with separate native authentication. */
@jakarta.ws.rs.ext.Provider
@jakarta.enterprise.inject.Vetoed
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public final class ProtectedInvitationResource implements RealmResourceProvider {
  private final KeycloakSession session;
  private final ProtectedInvitationConfiguration config;
  private final LifecycleAuthorization crypto;
  private final ProtectedInvitationAuthorization machineAuthorization;

  ProtectedInvitationResource(KeycloakSession session, ProtectedInvitationConfiguration config, LifecycleAuthorization crypto) {
    this.session = session; this.config = config; this.crypto = crypto;
    this.machineAuthorization = new ProtectedInvitationAuthorization(config, crypto);
  }

  @PUT
  @Path("v1/approvals/{approval}")
  public Response approve(@PathParam("approval") String approval, byte[] raw) {
    return guarded(() -> issueApproval(approval, raw));
  }

  @PUT
  @Path("v1/approvals/{approval}/attempts/{attempt}")
  public Response create(@PathParam("approval") String approval, @PathParam("attempt") String attempt,
      byte[] raw, @HeaderParam("X-ORISO-Task-Context") String proof) {
    return guarded(() -> accountCommand("create", approval, attempt, raw, proof));
  }

  @POST
  @Path("v1/approvals/{approval}/attempts/{attempt}/owned-read")
  public Response read(@PathParam("approval") String approval, @PathParam("attempt") String attempt,
      byte[] raw, @HeaderParam("X-ORISO-Task-Context") String proof) {
    return guarded(() -> accountCommand("owned-read", approval, attempt, raw, proof));
  }

  private Response accountCommand(String command, String approval, String attempt, byte[] raw, String proof) {
    if (!Set.of("create", "owned-read").contains(command)) deny();
    boolean create = "create".equals(command);
    uuid(approval); uuid(attempt);
    var body = parse(raw);
    if (create) fields(body, "approvalReceipt", "scopeDigest", "authorizationRevision", "acceptanceClaim",
        "execution", "account", "creationFingerprint");
    else fields(body, "approvalReceipt", "scopeDigest", "authorizationRevision", "creationFingerprint",
        "execution", "accountId", "creationProof");
    var em = lockedRealm();
    var row = em.find(ProtectedInvitationApproval.class, key(config.realmId, approval), LockModeType.PESSIMISTIC_WRITE);
    if (row != null) em.refresh(row);
    String attemptKey = protectedAttemptKey(config.realmId, approval, attempt);
    var currentAttempt = em.find(AccountLifecycleAttempt.class, attemptKey, LockModeType.PESSIMISTIC_WRITE);
    if (currentAttempt != null) em.refresh(currentAttempt);
    // Current native grant checks run after the relevant provenance locks.
    var machine = machineAuthorization.requireMachine(session, Set.of("ACCOUNT_CREATE"));
    crypto.verifyProtectedCommand(proof, machine, "protected-account." + command, create ? "PUT" : "POST",
        "realm/" + config.realmId + "/protected-invitation/" + approval + "/account-attempt/" + attempt, body);
    if (row == null) deny();
    if (row.approvalReceipt == null || !canonical(body.path("approvalReceipt")).equals(row.approvalReceipt)
        || !LifecycleAuthorization.equal(row.scopeDigest, text(body, "scopeDigest", 64, false))
        || row.authorizationRevision != number(body, "authorizationRevision", true)) deny();
    var scope = parse(row.request).path("scope");
    if (!machine.clientId().equals(scope.path("creatorClient").asText())
        || !machine.subject().equals(scope.path("creatorSubject").asText())) deny();
    if (!create && currentAttempt == null) deny();
    var acceptance = create ? body.path("acceptanceClaim")
        : parse(currentAttempt.scope).path("approvalBinding").path("acceptanceClaim");
    fields(acceptance, "workflowId", "inviteId", "authorizationRevision", "claimId", "journalVersion");
    if (!row.workflowId.equals(uuid(text(acceptance, "workflowId", 36, false)))
        || !row.inviteId.equals(text(acceptance, "inviteId", 255, false))
        || row.authorizationRevision != number(acceptance, "authorizationRevision", true)) deny();
    uuid(text(acceptance, "claimId", 36, false));
    number(acceptance, "journalVersion", true);
    execution(body.path("execution"));
    if (create && number(body.path("execution"), "generation", false) != 0) conflict();
    String fingerprint = text(body, "creationFingerprint", 64, false);
    hex(fingerprint);
    if (create) {
      var fingerprintInput = body.deepCopy();
      ((com.fasterxml.jackson.databind.node.ObjectNode) fingerprintInput).remove("creationFingerprint");
      if (!LifecycleAuthorization.equal(fingerprint, crypto.mac("protected-account-creation/v1", fingerprintInput))) deny();
      var account = body.path("account");
      String recipient = scope.path("recipient").asText();
      if (!recipient.equals(text(account, "email", 255, false))
          || !encodedUsername(recipient).equals(text(account, "username", 255, false))) deny();
    } else if (!LifecycleAuthorization.equal(fingerprint, currentAttempt.creationFingerprint)) deny();
    var enriched = parse(row.scope);
    var frozenProfile = enriched.path("profile");
    var internalScope = JSON.createObjectNode();
    internalScope.put("tenantId", Long.toString(HumanPolicyJson.tenants(scope.path("targetTenantIds")).iterator().next()));
    internalScope.put("registrationKind", scope.path("protectedKind").asText());
    internalScope.put("initialGroup", frozenProfile.path("groupPath").asText());
    var origin = internalScope.putObject("origin");
    origin.put("kind", "INVITATION"); origin.put("workflowId", row.workflowId);
    origin.put("provenance", "protected-approval-v1:" + approval);
    origin.put("humanIssuer", enriched.path("issuer").asText());
    origin.put("humanSubject", row.issuerSubject); origin.put("humanAuthority", enriched.path("authority").asText());
    var agencies = origin.putArray("agencyIds");
    if (!scope.path("agencyBinding").isNull()) agencies.add(Long.toString(number(scope.path("agencyBinding"), "agencyId", true)));
    var approvalBinding = internalScope.putObject("approvalBinding");
    approvalBinding.put("approvalId", approval); approvalBinding.put("scopeDigest", row.scopeDigest);
    approvalBinding.put("authorizationRevision", row.authorizationRevision);
    approvalBinding.set("acceptanceClaim", acceptance.deepCopy());
    var translated = JSON.createObjectNode();
    var identity = translated.putObject("identity");
    identity.set("scope", internalScope); identity.put("creationFingerprint", fingerprint);
    translated.set("execution", body.path("execution").deepCopy());
    if (create) translated.set("account", body.path("account").deepCopy());
    else {
      translated.set("accountId", body.path("accountId").deepCopy());
      translated.set("creationProof", body.path("creationProof").deepCopy());
    }
    var binding = new AccountLifecycleResource.LifecycleBinding(attemptKey, machine.clientId(), machine.subject(),
        internalScope, fingerprint, text(frozenProfile, "groupId", 255, false),
        crypto.mac("protected-initial-profile/v1", frozenProfile));
    // The concrete policy is private and is minted only after original-wire proof
    // verification and realm -> approval -> attempt locks. It is never a DTO/claim.
    var policy = new ProtectedLifecyclePolicy(row, attempt, binding, frozenProfile, translated,
        crypto.mac("protected-invitation-payload/v1", body));
    return new AccountLifecycleResource(session, crypto, Map.of())
        .executeProtected(command, attempt, translated, machine.actor(), policy);
  }

  private final class ProtectedLifecyclePolicy implements AccountLifecycleResource.LifecyclePolicy {
    private final ProtectedInvitationApproval approval;
    private final String attempt, profileJson, internalJson, originalCommandDigest;
    private final AccountLifecycleResource.LifecycleBinding binding;

    private ProtectedLifecyclePolicy(ProtectedInvitationApproval approval, String attempt,
        AccountLifecycleResource.LifecycleBinding binding, JsonNode profile, JsonNode internalBody,
        String originalCommandDigest) {
      this.approval = approval; this.attempt = attempt; this.binding = binding;
      this.profileJson = canonical(profile); this.internalJson = canonical(internalBody);
      this.originalCommandDigest = originalCommandDigest;
    }

    public AccountLifecycleResource.LifecycleBinding binding() { return binding; }

    public GroupModel approvedGroup(RealmModel realm) {
      var profile = parse(profileJson);
      var current = config.profiles.get(text(profile, "id", 255, false));
      if (current == null || !profileJson.equals(canonical(current.snapshot()))) deny();
      config.validateProfile(session, current);
      var group = session.groups().getGroupById(realm, binding.groupId());
      if (group == null || !binding.groupId().equals(group.getId())) conflict();
      return group;
    }

    public void verifyCreate(JsonNode internalBody) {
      if (!internalJson.equals(canonical(internalBody))) deny();
    }

    public String commandDigest() { return originalCommandDigest; }

    public void before(String command, AccountLifecycleAttempt current, EntityManager em) {
      if (!Set.of("create", "owned-read").contains(command)
          || !Instant.parse(approval.validUntil).isAfter(Instant.now())) conflict();
      if (current == null) {
        if (!"create".equals(command) || !"AUTHORIZED".equals(approval.state) || approval.boundAttemptId != null) conflict();
      } else if (!"BOUND".equals(approval.state) || !attempt.equals(approval.boundAttemptId)) conflict();
    }

    public void after(String command, AccountLifecycleAttempt current, EntityManager em) {
      if (!"create".equals(command) || current == null || !"OPEN".equals(current.state)
          || current.accountId == null || !"AUTHORIZED".equals(approval.state)
          || approval.boundAttemptId != null || !attempt.equals(current.attemptId)
          || !Instant.parse(approval.validUntil).isAfter(Instant.now())) conflict();
      approval.boundAttemptId = attempt; approval.state = "BOUND";
      // Same request/JPA transaction as the native user, proof and attempt. A
      // callback/flush failure rolls every effect back; no separate transaction.
      em.flush();
    }
  }

  private static String encodedUsername(String recipient) {
    if (recipient.startsWith("enc.")) return recipient;
    // Pinned UserService UsernameTranscoder v1, RFC4648 Base32 then '=' -> '.'.
    String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var encoded = new StringBuilder();
    int buffer = 0, bits = 0;
    for (byte value : recipient.getBytes(StandardCharsets.UTF_8)) {
      buffer = (buffer << 8) | (value & 255); bits += 8;
      while (bits >= 5) { bits -= 5; encoded.append(alphabet.charAt((buffer >>> bits) & 31)); }
    }
    if (bits > 0) encoded.append(alphabet.charAt((buffer << (5 - bits)) & 31));
    while (encoded.length() % 8 != 0) encoded.append('.');
    return "enc." + encoded;
  }

  private static String protectedAttemptKey(String realm, String approval, String attempt) {
    var tuple = JSON.createObjectNode(); tuple.put("realmId", realm); tuple.put("approvalId", approval); tuple.put("attemptId", attempt);
    try {
      return "protected-attempt:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
          .digest(("protected-account-attempt/v1\n" + canonical(tuple)).getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException("SHA256 unavailable"); }
  }

  private Response issueApproval(String approval, byte[] raw) {
    uuid(approval);
    var request = parse(raw);
    fields(request, "scope");
    var scope = request.path("scope");
    var em = lockedRealm();
    String key = key(config.realmId, approval);
    var row = em.find(ProtectedInvitationApproval.class, key, LockModeType.PESSIMISTIC_WRITE);
    if (row != null) em.refresh(row);
    // Native authentication is independent of the task context key. The explicit
    // subject selects one installed policy; a token never selects authority data.
    var nativeHuman = NativeHumanBearer.require(session);
    var binding = config.bindings.get(nativeHuman.getUser().getId());
    if (binding == null) deny();
    var human = CurrentHumanAuthorization.require(session, binding.policy());
    if (row != null && !"AUTHORIZED".equals(row.state)) conflict();
    if (row != null && !Instant.parse(row.validUntil).isAfter(Instant.now())) conflict();
    var profile = validateScope(scope, binding, human);
    String requestJson = canonical(request);
    var requestBinding = JSON.createObjectNode();
    requestBinding.set("request", request);
    requestBinding.put("issuerRealm", human.realmId());
    requestBinding.put("issuerSubject", human.subject());
    String requestDigest = crypto.mac("protected-approval-request/v1", requestBinding);
    if (row != null) {
      if (!row.issuerSubject.equals(human.subject()) || !row.request.equals(requestJson)
          || !LifecycleAuthorization.equal(row.requestDigest, requestDigest)
          || !"AUTHORIZED".equals(row.state)) conflict();
      return result(row, 200);
    }
    Instant expires = Instant.parse(text(scope, "validUntil", 30, false)), now = Instant.now();
    // Actual AccountInviteService.validExpiryDays permits at most365days.
    if (!expires.isAfter(now) || expires.isAfter(now.plusSeconds(365L * 24 * 60 * 60))) deny();
    config.validateProfile(session, profile);
    var enriched = JSON.createObjectNode();
    enriched.set("scope", scope);
    enriched.put("realmId", human.realmId());
    enriched.put("issuerSubject", human.subject());
    enriched.put("issuer", human.issuer());
    enriched.put("issuerClient", human.clientId());
    enriched.put("authority", binding.authority());
    enriched.put("bindingVersion", human.policyVersion());
    enriched.set("issuerRealmRoles", JSON.valueToTree(new TreeSet<>(human.realmRoles())));
    var issuerClientRoles = new TreeMap<String, Set<String>>();
    human.clientRoles().forEach((id, roles) -> issuerClientRoles.put(id, new TreeSet<>(roles)));
    enriched.set("issuerClientRoles", JSON.valueToTree(issuerClientRoles));
    enriched.set("profile", profile.snapshot());
    row = new ProtectedInvitationApproval();
    row.id = key; row.realmId = human.realmId(); row.approvalId = approval;
    row.workflowId = text(scope, "workflowId", 36, false);
    row.inviteId = text(scope, "inviteId", 255, false);
    row.authorizationRevision = number(scope, "authorizationRevision", true);
    row.request = requestJson; row.requestDigest = requestDigest;
    row.scope = canonical(enriched); row.scopeDigest = crypto.mac("protected-approval-scope/v1", enriched);
    row.issuerSubject = human.subject(); row.validUntil = text(scope, "validUntil", 30, false); row.state = "AUTHORIZED";
    var receipt = JSON.createObjectNode();
    receipt.put("approvalId", approval); receipt.put("scopeDigest", row.scopeDigest);
    receipt.put("issuerSubject", human.subject()); receipt.put("bindingVersion", human.policyVersion());
    receipt.put("profileVersion", profile.version()); receipt.put("validUntil", scope.path("validUntil").asText());
    receipt.put("approvalRequestDigest", requestDigest);
    receipt.put("receipt", crypto.receipt("protected-approval-receipt/v1", receipt.deepCopy()));
    row.approvalReceipt = canonical(receipt);
    em.persist(row);
    em.flush();
    return result(row, 201);
  }

  @POST
  @Path("v1/approvals/{approval}/cancel")
  public Response cancel(@PathParam("approval") String approval, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof) {
    return guarded(() -> cancelKnown(approval, raw, proof));
  }

  private Response cancelKnown(String approval, byte[] raw, String proof) {
    uuid(approval);
    var body = parse(raw);
    fields(body, "cancellationId", "scopeDigest", "workflowId", "inviteId", "authorizationRevision",
        "reason", "absentScope", "approvalRequestDigest");
    String cancellationId = uuid(text(body, "cancellationId", 36, false));
    uuid(text(body, "workflowId", 36, false));
    text(body, "inviteId", 255, false);
    number(body, "authorizationRevision", true);
    hex(text(body, "approvalRequestDigest", 64, false));
    String scopeDigest = text(body, "scopeDigest", 64, true);
    if (scopeDigest != null) hex(scopeDigest);
    String reason = text(body, "reason", 30, false);
    if (!Set.of("REVOKED", "SUPERSEDED", "ISSUANCE_ABORTED").contains(reason)) bad();
    var em = lockedRealm();
    var row = em.find(ProtectedInvitationApproval.class, key(config.realmId, approval), LockModeType.PESSIMISTIC_WRITE);
    if (row != null) em.refresh(row);
    LifecycleAuthorization.CheckedMachine machine = null;
    CurrentHumanAuthorization.VerifiedHuman human = null;
    ProtectedInvitationConfiguration.Binding binding = null;
    if (proof != null) {
      machine = machineAuthorization.requireMachine(session, Set.of("SETUP"));
      crypto.verifyProtectedCommand(proof, machine, "protected-invitation.cancel", "POST",
          "realm/" + config.realmId + "/protected-invitation/" + approval, body);
    } else {
      var nativeHuman = NativeHumanBearer.require(session);
      binding = config.bindings.get(nativeHuman.getUser().getId());
      if (binding == null) deny();
      human = CurrentHumanAuthorization.require(session, binding.policy());
    }
    boolean absent = row == null;
    if (absent) {
      if (machine == null || body.path("absentScope").isNull()) throw new NotFoundException();
      if (scopeDigest != null) conflict();
      row = restrictiveTombstone(approval, body, machine);
    } else if (!body.path("absentScope").isNull()) {
      // Proposed claims can only restrict their exact original proposal. They
      // cannot replace an existing true human approval or issuer snapshot.
      if (machine == null) conflict();
      var proposal = restrictiveTombstone(approval, body, machine);
      if (!proposal.request.equals(row.request) || !proposal.issuerSubject.equals(row.issuerSubject)
          || !LifecycleAuthorization.equal(proposal.requestDigest, row.requestDigest)) conflict();
    }
    var storedScope = parse(row.request).path("scope");
    if (machine != null && (!machine.clientId().equals(storedScope.path("setupClient").asText())
        || !machine.subject().equals(storedScope.path("setupSubject").asText()))) deny();
    if (binding != null && "TENANT_PEER".equals(binding.authority())
        && (!"TENANT_ADMIN".equals(storedScope.path("protectedKind").asText())
            || !storedScope.path("targetTenantIds").get(0).isIntegralNumber()
            || storedScope.path("targetTenantIds").get(0).asLong() != human.tenantId())) deny();
    if (!row.workflowId.equals(body.path("workflowId").asText()) || !row.inviteId.equals(body.path("inviteId").asText())
        || row.authorizationRevision != body.path("authorizationRevision").asLong()
        || !LifecycleAuthorization.equal(row.requestDigest, body.path("approvalRequestDigest").asText())
        || scopeDigest != null && !LifecycleAuthorization.equal(row.scopeDigest, scopeDigest)) conflict();
    String request = canonical(body);
    if (!absent && "CANCELLED".equals(row.state)) {
      if (row.cancellationId == null || row.cancellationRequest == null || row.transitionReceipt == null) conflict();
      if (cancellationId.equals(row.cancellationId)) {
        if (!row.cancellationRequest.equals(request)) conflict();
      } else {
        var original = parse(row.cancellationRequest).deepCopy();
        var retry = body.deepCopy();
        ((com.fasterxml.jackson.databind.node.ObjectNode) original).remove("cancellationId");
        ((com.fasterxml.jackson.databind.node.ObjectNode) retry).remove("cancellationId");
        if (!canonical(original).equals(canonical(retry))) conflict();
      }
      return result(row, 200);
    }
    if (!absent && (!"AUTHORIZED".equals(row.state) || !Instant.parse(row.validUntil).isAfter(Instant.now()))) conflict();
    row.state = "CANCELLED";
    row.cancellationId = cancellationId;
    row.cancellationRequest = request;
    var transition = JSON.createObjectNode();
    transition.put("realmId", row.realmId); transition.put("approvalId", row.approvalId);
    transition.put("workflowId", row.workflowId); transition.put("inviteId", row.inviteId);
    transition.put("authorizationRevision", row.authorizationRevision);
    transition.put("scopeDigest", row.scopeDigest); transition.put("approvalRequestDigest", row.requestDigest);
    transition.put("operation", "protected-invitation.cancel"); transition.put("cancellationId", cancellationId);
    transition.put("reason", reason); transition.put("state", "CANCELLED");
    transition.put("actor", machine == null ? "HUMAN" : machine.actor());
    transition.put("actorSubject", machine == null ? human.subject() : machine.subject());
    transition.put("actorIssuer", machine == null ? human.issuer() : config.issuer);
    transition.put("actorClient", machine == null ? human.clientId() : machine.clientId());
    if (machine == null) transition.put("actorBindingVersion", human.policyVersion());
    else transition.putNull("actorBindingVersion");
    transition.put("receipt", crypto.receipt("protected-approval-cancel/v1", transition.deepCopy()));
    row.transitionReceipt = canonical(transition);
    if (absent) em.persist(row);
    em.flush();
    return result(row, 200);
  }

  private ProtectedInvitationApproval restrictiveTombstone(String approval, JsonNode cancellation,
      LifecycleAuthorization.CheckedMachine machine) {
    var absentScope = cancellation.path("absentScope");
    var scope = absentScope.deepCopy();
    if (!scope.isObject()) bad();
    var object = (com.fasterxml.jackson.databind.node.ObjectNode) scope;
    String issuerRealm = text(scope, "originalIssuerRealm", 255, false);
    String issuerSubject = uuid(text(scope, "originalIssuerSubject", 36, false));
    object.remove(List.of("originalIssuerRealm", "originalIssuerSubject"));
    validateScopeShape(scope);
    if (!config.realmId.equals(issuerRealm) || !machine.clientId().equals(scope.path("setupClient").asText())
        || !machine.subject().equals(scope.path("setupSubject").asText())) deny();
    if (!scope.path("workflowId").equals(cancellation.path("workflowId"))
        || !scope.path("inviteId").equals(cancellation.path("inviteId"))
        || !scope.path("authorizationRevision").equals(cancellation.path("authorizationRevision"))) conflict();
    var request = JSON.createObjectNode(); request.set("scope", scope);
    var digestInput = JSON.createObjectNode(); digestInput.set("request", request);
    digestInput.put("issuerRealm", issuerRealm); digestInput.put("issuerSubject", issuerSubject);
    String requestDigest = crypto.mac("protected-approval-request/v1", digestInput);
    if (!LifecycleAuthorization.equal(requestDigest, cancellation.path("approvalRequestDigest").asText())) conflict();
    var restriction = JSON.createObjectNode(); restriction.set("scope", scope);
    restriction.put("realmId", config.realmId); restriction.put("originalIssuerRealm", issuerRealm);
    restriction.put("originalIssuerSubject", issuerSubject); restriction.put("restrictionOnly", true);
    var row = new ProtectedInvitationApproval();
    row.id = key(config.realmId, approval); row.realmId = config.realmId; row.approvalId = approval;
    row.workflowId = scope.path("workflowId").asText(); row.inviteId = scope.path("inviteId").asText();
    row.authorizationRevision = scope.path("authorizationRevision").asLong();
    row.request = canonical(request); row.requestDigest = requestDigest; row.issuerSubject = issuerSubject;
    row.scope = canonical(restriction); row.scopeDigest = crypto.mac("protected-approval-scope/v1", restriction);
    row.validUntil = scope.path("validUntil").asText(); row.state = "CANCELLED";
    // Null approvalReceipt is a permanent non-authorizing type distinction.
    return row;
  }

  @POST
  @Path("v1/approvals/{approval}/status")
  public Response status(@PathParam("approval") String approval, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof) {
    return guarded(() -> setupStatus(approval, raw, proof));
  }

  private Response setupStatus(String approval, byte[] raw, String proof) {
    uuid(approval);
    var body = parse(raw);
    fields(body, "scopeDigest", "workflowId", "inviteId", "authorizationRevision", "attemptId", "approvalRequestDigest");
    uuid(text(body, "workflowId", 36, false));
    text(body, "inviteId", 255, false);
    number(body, "authorizationRevision", true);
    hex(text(body, "approvalRequestDigest", 64, false));
    String scopeDigest = text(body, "scopeDigest", 64, true);
    if (scopeDigest != null) hex(scopeDigest);
    String attempt = text(body, "attemptId", 36, true);
    if (attempt != null) uuid(attempt);
    var em = lockedRealm();
    var row = em.find(ProtectedInvitationApproval.class, key(config.realmId, approval), LockModeType.PESSIMISTIC_WRITE);
    if (row != null) em.refresh(row);
    var machine = machineAuthorization.requireMachine(session, Set.of("SETUP"));
    // The route selects the protected MAC domains and binds the original wire
    // bytes semantically before any future internal lifecycle translation.
    crypto.verifyProtectedCommand(proof, machine, "protected-invitation.status", "POST",
        "realm/" + config.realmId + "/protected-invitation/" + approval, body);
    if (row == null) throw new NotFoundException();
    var scope = parse(row.request).path("scope");
    if (!machine.clientId().equals(scope.path("setupClient").asText())
        || !machine.subject().equals(scope.path("setupSubject").asText())
        || !row.workflowId.equals(body.path("workflowId").asText())
        || !row.inviteId.equals(body.path("inviteId").asText())
        || row.authorizationRevision != body.path("authorizationRevision").asLong()
        || !LifecycleAuthorization.equal(row.requestDigest, body.path("approvalRequestDigest").asText())
        || scopeDigest != null && !LifecycleAuthorization.equal(row.scopeDigest, scopeDigest)
        || attempt != null && !attempt.equals(row.boundAttemptId)) deny();
    materializeAuthorizedExpiry(row, em);
    return result(row, 200);
  }

  private void materializeAuthorizedExpiry(ProtectedInvitationApproval row, EntityManager em) {
    if (!"AUTHORIZED".equals(row.state) || Instant.parse(row.validUntil).isAfter(Instant.now())) return;
    if (row.approvalReceipt == null || row.boundAttemptId != null || row.transitionReceipt != null) conflict();
    row.state = "EXPIRED";
    var transition = JSON.createObjectNode();
    transition.put("realmId", row.realmId); transition.put("approvalId", row.approvalId);
    transition.put("workflowId", row.workflowId); transition.put("inviteId", row.inviteId);
    transition.put("authorizationRevision", row.authorizationRevision);
    transition.put("scopeDigest", row.scopeDigest); transition.put("approvalRequestDigest", row.requestDigest);
    transition.put("operation", "protected-invitation.expire"); transition.put("reason", "EXPIRED");
    transition.put("state", "EXPIRED"); transition.put("actor", "RECEIVER");
    transition.put("expiryId", UUID.randomUUID().toString());
    transition.put("validUntil", row.validUntil); transition.put("expiredAt", Instant.now().toString());
    transition.put("receipt", crypto.receipt("protected-approval-expire/v1", transition.deepCopy()));
    row.transitionReceipt = canonical(transition);
    em.flush();
  }

  private EntityManager lockedRealm() {
    var em = CurrentNativeHumanIdentity.entityManager(session);
    var realm = em.find(RealmEntity.class, config.realmId, LockModeType.PESSIMISTIC_WRITE);
    if (realm == null || !config.realmId.equals(session.getContext().getRealm().getId())) deny();
    em.refresh(realm);
    return em;
  }

  private Response guarded(Supplier<Response> command) {
    try { return command.get(); }
    catch (WebApplicationException failure) {
      session.getTransactionManager().setRollbackOnly();
      return Response.status(failure.getResponse().getStatus()).entity(Map.of("error", "Protected invitation rejected"))
          .header("Cache-Control", "no-store").build();
    } catch (RuntimeException failure) {
      session.getTransactionManager().setRollbackOnly();
      // Never log exception messages/request values or bearer material.
      org.jboss.logging.Logger.getLogger(ProtectedInvitationResource.class)
          .errorf("Protected invitation transaction rolled back (%s)", failure.getClass().getName());
      return Response.status(503).entity(Map.of("error", "Protected invitation unavailable"))
          .header("Cache-Control", "no-store").build();
    }
  }

  private ProtectedInvitationConfiguration.Profile validateScope(JsonNode scope,
      ProtectedInvitationConfiguration.Binding binding, CurrentHumanAuthorization.VerifiedHuman human) {
    validateScopeShape(scope);
    String kind = scope.path("protectedKind").asText(), mode = scope.path("tenantMode").asText();
    long tenant = HumanPolicyJson.tenants(scope.get("targetTenantIds")).iterator().next();
    if ("TENANT_PEER".equals(binding.authority())
        && (!"TENANT_ADMIN".equals(kind) || !"EXISTING".equals(mode) || tenant != human.tenantId())) deny();
    String profileId = text(scope, "protectedProfileId", 255, false);
    var profile = config.profiles.get(profileId);
    if (!binding.profiles().contains(profileId) || profile == null || !kind.equals(profile.kind()) || !profile.modes().contains(mode)) deny();
    return profile;
  }

  private void validateScopeShape(JsonNode scope) {
    fields(scope, "workflowId", "inviteId", "authorizationRevision", "purpose", "recipient", "protectedKind",
        "targetTenantIds", "tenantMode", "reservationBinding", "agencyBinding", "protectedProfileId", "validUntil",
        "creatorClient", "creatorSubject", "setupClient", "setupSubject");
    uuid(text(scope, "workflowId", 36, false));
    text(scope, "inviteId", 255, false);
    number(scope, "authorizationRevision", true);
    if (!"INVITE".equals(text(scope, "purpose", 20, false))) deny();
    String recipient = text(scope, "recipient", 320, false);
    if (!recipient.equals(recipient.trim().toLowerCase(Locale.ROOT)) || !recipient.matches("[^\\s@]+@[^\\s@]+")) deny();
    String kind = text(scope, "protectedKind", 30, false), mode = text(scope, "tenantMode", 20, false);
    var targets = HumanPolicyJson.tenants(scope.get("targetTenantIds"));
    if (targets.size() != 1) deny();
    long tenant = targets.iterator().next();
    if (!("PLATFORM_ADMIN".equals(kind) && tenant == 0 && "EXISTING".equals(mode))
        && !("TENANT_ADMIN".equals(kind) && tenant > 0 && Set.of("EXISTING", "RESERVED_NEW").contains(mode))) deny();
    if (!"backend-account-create".equals(text(scope, "creatorClient", 255, false))
        || !config.actors.get("ACCOUNT_CREATE").equals(uuid(text(scope, "creatorSubject", 36, false)))
        || !"backend-setup".equals(text(scope, "setupClient", 255, false))
        || !config.actors.get("SETUP").equals(uuid(text(scope, "setupSubject", 36, false)))) deny();
    var reservation = scope.get("reservationBinding");
    if ("RESERVED_NEW".equals(mode)) {
      fields(reservation, "tenantId", "invitationWorkflowId", "capabilityDigest");
      if (number(reservation, "tenantId", true) != tenant
          || !scope.path("workflowId").asText().equals(uuid(text(reservation, "invitationWorkflowId", 36, false)))) deny();
      hex(text(reservation, "capabilityDigest", 64, false));
    } else if (!reservation.isNull()) deny();
    var agency = scope.get("agencyBinding");
    if (!agency.isNull()) {
      fields(agency, "agencyId", "tenantId");
      number(agency, "agencyId", true);
      if (number(agency, "tenantId", true) != tenant || "PLATFORM_ADMIN".equals(kind)) deny();
    }
    String deadline = text(scope, "validUntil", 30, false);
    try { if (!Instant.parse(deadline).toString().equals(deadline)) bad(); }
    catch (java.time.DateTimeException failure) { bad(); }
    text(scope, "protectedProfileId", 255, false);
  }

  static String key(String realm, String approval) {
    try {
      return "protected-approval:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
          .digest((realm + "\n" + approval).getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException("SHA256 unavailable"); }
  }

  private static void conflict() { throw new ClientErrorException(409); }

  private Response result(ProtectedInvitationApproval row, int status) {
    var result = JSON.createObjectNode();
    result.put("approvalId", row.approvalId); result.put("scopeDigest", row.scopeDigest);
    result.put("state", row.state); result.put("version", row.version);
    result.put("boundAttemptId", row.boundAttemptId); result.putNull("fencedExecution");
    if (row.approvalReceipt == null) result.putNull("approvalReceipt");
    else result.set("approvalReceipt", parse(row.approvalReceipt));
    if (row.transitionReceipt == null) result.putNull("transitionReceipt");
    else result.set("transitionReceipt", parse(row.transitionReceipt));
    result.put("approvalRequestDigest", row.requestDigest);
    return Response.status(status).entity(result).header("Cache-Control", "no-store").build();
  }

  public Object getResource() { return this; }
  public void close() {}
}
