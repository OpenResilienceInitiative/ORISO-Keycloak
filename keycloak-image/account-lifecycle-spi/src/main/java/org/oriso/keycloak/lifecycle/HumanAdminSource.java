package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import org.keycloak.models.KeycloakSession;

/** Actual current primary or consumed peer. Installation selectors alone cannot construct this. */
final class HumanAdminSource {
  private final ProtectedPeerDelegation.Resolved resolved;
  private final CurrentHumanAuthorization.VerifiedHuman human;
  private HumanAdminSource(ProtectedInvitationConfiguration config,
      ProtectedPeerDelegation.Resolved resolved, CurrentHumanAuthorization.VerifiedHuman human) {
    this.resolved = resolved; this.human = human;
  }
  static HumanAdminSource require(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String header) {
    var origin = request.target().path("origin");
    if (!"HUMAN_ADMIN".equals(origin.path("kind").asText())
        || !"PROTECTED_ACCOUNT_OPERATIONS_V1".equals(origin.path("humanAuthority").asText())) deny();
    if (header == null || header.length() > 32775 || !header.regionMatches(true, 0, "Bearer ", 0, 7))
      throw new jakarta.ws.rs.NotAuthorizedException("Bearer");
    String bearer = header.substring(7);
    var config = ProtectedInvitationFactory.checkedBootstrapConfiguration(session);
    var delegation = new ProtectedPeerDelegation(session, config, crypto);
    var located = NativeHumanBearer.require(session, bearer);
    var resolved = delegation.resolve(located, CurrentNativeHumanIdentity.entityManager(session));
    var human = delegation.require(resolved, bearer);
    if (!human.subject().equals(origin.path("humanSubject").asText())
        || !human.issuer().equals(origin.path("humanIssuer").asText())
        || !human.clientId().equals(origin.path("humanClient").asText())
        || "PLATFORM".equals(resolved.binding().authority()) && human.tenantId() != 0
        || "TENANT_PEER".equals(resolved.binding().authority()) && human.tenantId() <= 0) deny();
    return new HumanAdminSource(config, resolved, human);
  }
  String authority() { return resolved.binding().authority(); }
  long tenant() { return human.tenantId(); }
  String subject() { return human.subject(); }
  void targetTenant(com.fasterxml.jackson.databind.JsonNode tenant) {
    if ("TENANT_PEER".equals(authority())
        && (!tenant.isTextual() || !Long.toString(human.tenantId()).equals(tenant.asText()))) deny();
  }
  @Override public String toString() { return "HumanAdminSource[redacted]"; }
}
