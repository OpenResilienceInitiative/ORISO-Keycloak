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
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.services.resource.RealmResourceProvider;

/** Human-owned approval issuance. No native user is created by this resource. */
@jakarta.ws.rs.ext.Provider
@jakarta.enterprise.inject.Vetoed
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public final class ProtectedInvitationResource implements RealmResourceProvider {
  private final KeycloakSession session;
  private final ProtectedInvitationConfiguration config;
  private final LifecycleAuthorization crypto;

  ProtectedInvitationResource(KeycloakSession session, ProtectedInvitationConfiguration config, LifecycleAuthorization crypto) {
    this.session = session; this.config = config; this.crypto = crypto;
  }

  @PUT
  @Path("v1/approvals/{approval}")
  public Response approve(@PathParam("approval") String approval, byte[] raw) {
    try {
      uuid(approval);
      var request = parse(raw);
      fields(request, "scope");
      var scope = request.path("scope");
      var em = CurrentNativeHumanIdentity.entityManager(session);
      var realm = em.find(RealmEntity.class, config.realmId, LockModeType.PESSIMISTIC_WRITE);
      if (realm == null || !config.realmId.equals(session.getContext().getRealm().getId())) deny();
      em.refresh(realm);
      String key = key(config.realmId, approval);
      var row = em.find(ProtectedInvitationApproval.class, key, LockModeType.PESSIMISTIC_WRITE);
      if (row != null) em.refresh(row);
      // Native authentication is independent of the task context key. The explicit
      // subject selects one installed policy; a token never selects authority data.
      var nativeHuman = NativeHumanBearer.require(session);
      var binding = config.bindings.get(nativeHuman.getUser().getId());
      if (binding == null) deny();
      var human = CurrentHumanAuthorization.require(session, binding.policy());
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
    } catch (WebApplicationException failure) {
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
    if ("TENANT_PEER".equals(binding.authority())
        && (!"TENANT_ADMIN".equals(kind) || !"EXISTING".equals(mode) || tenant != human.tenantId())) deny();
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
    String profileId = text(scope, "protectedProfileId", 255, false);
    var profile = config.profiles.get(profileId);
    if (!binding.profiles().contains(profileId) || profile == null || !kind.equals(profile.kind()) || !profile.modes().contains(mode)) deny();
    return profile;
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
    result.putNull("boundAttemptId"); result.putNull("fencedExecution");
    result.set("approvalReceipt", parse(row.approvalReceipt));
    result.putNull("transitionReceipt"); result.put("approvalRequestDigest", row.requestDigest);
    return Response.status(status).entity(result).header("Cache-Control", "no-store").build();
  }

  public Object getResource() { return this; }
  public void close() {}
}
