package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import org.keycloak.models.KeycloakSession;

/** Actual current primary or consumed peer. Installation selectors alone cannot construct this. */
final class HumanAdminSource {
  private final ProtectedInvitationConfiguration config;
  private final OrdinaryAdminSource ordinary;
  private final ProtectedPeerDelegation.Resolved resolved;
  private final CurrentHumanAuthorization.VerifiedHuman human;
  private HumanAdminSource(ProtectedInvitationConfiguration config,
      ProtectedPeerDelegation.Resolved resolved, CurrentHumanAuthorization.VerifiedHuman human) {
    this.config = config; this.resolved = resolved; this.human = human;this.ordinary=null;
  }
  private HumanAdminSource(OrdinaryAdminSource ordinary){
    this.config=null;this.resolved=null;this.human=null;this.ordinary=ordinary;
  }
  static HumanAdminSource require(KeycloakSession session, LifecycleAuthorization crypto,
      MaintenanceRequest request, String header) {
    return require(session,crypto,request.target().path("origin"),request.target().path("tenantId"),header);
  }
  static HumanAdminSource require(KeycloakSession session,LifecycleAuthorization crypto,
      com.fasterxml.jackson.databind.JsonNode origin,com.fasterxml.jackson.databind.JsonNode tenant,String header) {
    if("HUMAN_ADMIN".equals(origin.path("kind").asText())&&"ORDINARY_ACCOUNT_OPERATIONS_V1".equals(origin.path("humanAuthority").asText()))
      return new HumanAdminSource(AccountLifecycleFactory.checkedOrdinarySource(session,crypto,origin,tenant,header));
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
  void requireProtectedInvitationProfile(KeycloakSession session,InvitationEmailAvailability request) {
    if(ordinary!=null)deny();
    var profile=config.profiles.get(request.profileId());
    if(profile==null||profile.version()!=request.profileVersion()||!profile.kind().equals(request.kind())
        ||!resolved.binding().profiles().contains(profile.id())||!profile.modes().contains(request.tenantMode())
        ||"TENANT_PEER".equals(authority())&&(!"TENANT_ADMIN".equals(request.kind())||!"EXISTING".equals(request.tenantMode())))deny();
    config.validateProfile(session,profile);
  }
  String authority() { return ordinary==null?resolved.binding().authority():"ORDINARY"; }
  String ordinaryProfile(){return ordinary==null?null:ordinary.profile.id;}
  long tenant() { return ordinary==null?human.tenantId():ordinary.human.tenantId(); }
  String subject() { return ordinary==null?human.subject():ordinary.human.subject(); }
  void protectedOperation(String account,String profile,String operation) {
    if(ordinary!=null)deny();
    requireProtectedOperations(config,resolved,human,account,java.util.Set.of(profile),java.util.Set.of(operation));
  }
  static void requireProtectedOperations(ProtectedInvitationConfiguration config,
      ProtectedPeerDelegation.Resolved resolved,CurrentHumanAuthorization.VerifiedHuman human,
      String account,java.util.Set<String> profiles,java.util.Set<String> operations) {
    var grants=config.bindingAccountOperations.get(human.subject());
    if(resolved.sourceProfile()!=null){
      var policies=config.peerPolicies.values().stream().filter(policy -> policy.sourceProfileId().equals(resolved.sourceProfile().id())
          &&policy.sourceProfileVersion()==resolved.sourceProfile().version()).toList();
      if(policies.size()!=1)deny();grants=config.peerAccountOperations.get(policies.get(0).id());
    }
    if(grants==null)deny();
    for(String profile:profiles)for(String operation:operations)
      if(grants.stream().noneMatch(grant -> grant.authority().equals(resolved.binding().authority())
          &&grant.profiles().contains(profile)&&grant.operations().contains(operation)
          &&(!grant.selfOnly()||human.subject().equals(account))
          &&(grant.targetSubjects().isEmpty()||grant.targetSubjects().contains(account))))deny();
  }
  void targetTenant(com.fasterxml.jackson.databind.JsonNode tenant) {
    if (("TENANT_PEER".equals(authority())||"ORDINARY".equals(authority()))
        && (!tenant.isTextual() || !Long.toString(tenant()).equals(tenant.asText()))) deny();
  }
  @Override public String toString() { return "HumanAdminSource[redacted]"; }
}
