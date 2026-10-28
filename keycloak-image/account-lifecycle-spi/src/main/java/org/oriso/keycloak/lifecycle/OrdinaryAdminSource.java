package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import jakarta.persistence.LockModeType;
import java.util.*;
import org.keycloak.models.KeycloakSession;

/** Restricted ordinary operator: current native human plus pinned original ordinary incarnation. */
final class OrdinaryAdminSource {
  final CurrentNativeHumanIdentity.VerifiedHuman human;
  final GeneralPolicy.Profile profile;
  private OrdinaryAdminSource(CurrentNativeHumanIdentity.VerifiedHuman human,GeneralPolicy.Profile profile){this.human=human;this.profile=profile;}
  static boolean selected(com.fasterxml.jackson.databind.JsonNode target){
    return "HUMAN_ADMIN".equals(target.path("origin").path("kind").asText())
        &&"ORDINARY_ACCOUNT_OPERATIONS_V1".equals(target.path("origin").path("humanAuthority").asText());
  }
  static OrdinaryAdminSource require(KeycloakSession session,LifecycleAuthorization crypto,GeneralPolicy policy,
      Map<String,Set<String>> mappings,MaintenanceRequest request,String header){
    return require(session,crypto,policy,mappings,request.target().path("origin"),request.target().path("tenantId"),header);
  }
  static OrdinaryAdminSource require(KeycloakSession session,LifecycleAuthorization crypto,GeneralPolicy policy,
      Map<String,Set<String>> mappings,com.fasterxml.jackson.databind.JsonNode origin,
      com.fasterxml.jackson.databind.JsonNode targetTenant,String header){
    if(header==null||header.length()>32775||!header.regionMatches(true,0,"Bearer ",0,7))throw new jakarta.ws.rs.NotAuthorizedException("Bearer");
    if(!"HUMAN_ADMIN".equals(origin.path("kind").asText())||!"ORDINARY_ACCOUNT_OPERATIONS_V1".equals(origin.path("humanAuthority").asText()))deny();
    var realm=session.getContext().getRealm();var em=CurrentNativeHumanIdentity.entityManager(session);
    var locked=em.find(org.keycloak.models.jpa.entities.RealmEntity.class,realm.getId(),LockModeType.PESSIMISTIC_WRITE);
    if(locked==null)deny();em.refresh(locked);
    var human=CurrentNativeHumanIdentity.require(session,policy.nativePolicy,header.substring(7));
    if(!human.subject().equals(origin.path("humanSubject").asText())||!human.issuer().equals(origin.path("humanIssuer").asText())
        ||!human.clientId().equals(origin.path("humanClient").asText())||human.tenantId()==null||human.tenantId()<=0
        ||!Long.toString(human.tenantId()).equals(targetTenant.asText()))deny();
    if(!em.createNativeQuery("select ID from ORISO_ACCOUNT_MAINTENANCE_OP where REALM_ID=:realm and ACCOUNT_ID=:account and COMMAND='delete' for update")
        .setParameter("realm",realm.getId()).setParameter("account",human.subject()).getResultList().isEmpty())deny();
    var rows=em.createQuery("select a from AccountLifecycleAttempt a where a.realmId=:realm and a.accountId=:account",AccountLifecycleAttempt.class)
        .setParameter("realm",realm.getId()).setParameter("account",human.subject()).setLockMode(LockModeType.PESSIMISTIC_WRITE).setMaxResults(2).getResultList();
    GeneralPolicy.Profile baseline;com.fasterxml.jackson.databind.JsonNode tenant;String provenance;
    MaintenanceAdoption.Baseline adoption=null;
    if(rows.isEmpty()){
      if(ProtectedInvitationFactory.configuredAdoptedTarget(session,human.subject()))deny();
      var selected=policy.adoptedAccounts.get(human.subject());if(selected==null)deny();
      baseline=policy.profile(selected.profileId(),selected.profileVersion());
      adoption=MaintenanceAdoption.prepare(session,crypto,human.subject(),"ORDINARY",baseline.id,baseline.version,baseline.snapshot,JSON.valueToTree(Long.toString(human.tenantId())));
      tenant=adoption.tenant();provenance=adoption.provenance();
    }else{
      if(rows.size()!=1)deny();var row=rows.get(0);em.refresh(row);
      if(!"COMMITTED".equals(row.state)||!"commit".equals(row.terminalOperation)||!"backend-account-create".equals(row.ownerClient)
          ||!crypto.creatorSubject.equals(row.ownerSubject)||row.creationProof==null||row.terminalReceipt==null||row.terminalDigest==null)deny();
      var scope=parse(row.scope);LifecycleGroups.scope(scope);
      var roles=mappings.get(scope.path("initialGroup").asText());
      if(roles==null||!LifecycleAuthorization.equal(row.roleFingerprint,crypto.mac("initial-roles",JSON.valueToTree(new TreeSet<>(roles)))))deny();
      baseline=policy.profileForGroup(row.groupId,roles);OrdinaryAccountOperations.verifyCommitted(crypto,realm.getName(),row,scope);
      OriginalNativeBirth.require(em,crypto,row);
      var original=JSON.createObjectNode();original.put("attempt",row.id);original.put("creationProof",row.creationProof);
      original.put("terminalReceipt",row.terminalReceipt);original.set("scope",scope);
      provenance=crypto.mac("maintenance-provenance/v1",original);tenant=scope.path("tenantId");
    }
    var lineage=MaintenanceLineage.resolve(session,crypto,human.subject(),provenance,"ORDINARY",baseline.id,baseline.version,tenant,baseline.snapshot);
    var profile=policy.profile(lineage.profileId(),lineage.profileVersion());
    if(!"ORDINARY".equals(lineage.kind())||!canonical(profile.snapshot).equals(canonical(lineage.nativeProfile()))
        ||!Long.toString(human.tenantId()).equals(lineage.tenant().asText())
        ||!Set.of("AGENCY_ADMIN","CONSULTANT_AGENCY_ADMIN").contains(LifecycleGroups.allowedKind(profile.realmRoles))
        ||!profile.realmRoles.equals(mappings.get(profile.path))||!human.directGroupIds().equals(Set.of(profile.groupId))
        ||!human.currentGroups().keySet().equals(Set.of(profile.groupId,profile.parentId))
        ||!human.realmRoles().equals(profile.realmRoles)||!human.clientRoles().equals(profile.clientRoles))deny();
    policy.validateProfile(session,profile);LifecycleGroups.group(session,realm,profile.path,profile.realmRoles);
    if(adoption!=null)adoption.checked(session);
    return new OrdinaryAdminSource(human,profile);
  }
}
