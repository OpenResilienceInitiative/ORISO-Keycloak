package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import org.keycloak.models.KeycloakSession;

/** A transferred Consultant retains its original protected anchor and authenticated full lineage. */
final class ProtectedOrdinaryTransfer {
  record Checked(MaintenanceLineage.Current lineage, boolean originalPlatform) {}

  /** Routing hint only; every consuming path must call require before obtaining authority. */
  static boolean located(KeycloakSession session,String account){
    var rows=CurrentNativeHumanIdentity.entityManager(session).createQuery(
        "select l from AccountMaintenanceLineage l where l.realmId=:realm and l.accountId=:account order by l.sequence desc",AccountMaintenanceLineage.class)
        .setParameter("realm",session.getContext().getRealm().getId()).setParameter("account",account).setMaxResults(1).getResultList();
    return !rows.isEmpty()&&"ORDINARY".equals(parse(rows.get(0).snapshotJson).path("desired").path("profileKind").asText())
        && protectedOrigin(session,account);
  }
  private static boolean protectedOrigin(KeycloakSession session,String account){
    var scopes=CurrentNativeHumanIdentity.entityManager(session).createQuery(
        "select a.scope from AccountLifecycleAttempt a where a.realmId=:realm and a.accountId=:account",String.class)
        .setParameter("realm",session.getContext().getRealm().getId()).setParameter("account",account).setMaxResults(2).getResultList();
    if(scopes.size()>1)deny();
    return scopes.isEmpty()?ProtectedInvitationFactory.configuredAdoptedTarget(session,account):parse(scopes.get(0)).has("approvalBinding");
  }
  static Checked require(KeycloakSession session,LifecycleAuthorization crypto,String account){
    var checked=resolve(session,crypto,account,true);var lineage=checked.lineage();
    if(!"ORDINARY".equals(lineage.kind())||lineage.sequence()<1||lineage.digest()==null
        ||!java.util.Set.of("CONSULTANT","CONSULTANT_AGENCY_ADMIN").contains(LifecycleGroups.allowedKind(HumanPolicyJson.strings(lineage.nativeProfile().path("realmRoles"),1,10,255))))deny();
    return checked;
  }
  static Checked historical(KeycloakSession session,LifecycleAuthorization crypto,String account){
    return resolve(session,crypto,account,false);
  }
  private static Checked resolve(KeycloakSession session,LifecycleAuthorization crypto,String account,boolean live){
    var config=ProtectedInvitationFactory.checkedBootstrapConfiguration(session);
    var em=CurrentNativeHumanIdentity.entityManager(session);var realm=session.getContext().getRealm();
    if(!config.realmId.equals(realm.getId())||!config.realmName.equals(realm.getName()))deny();
    var locked=em.find(org.keycloak.models.jpa.entities.RealmEntity.class,realm.getId(),LockModeType.PESSIMISTIC_WRITE);
    if(locked==null)deny();em.refresh(locked);
    var locators=em.createQuery("select a.id,a.scope from AccountLifecycleAttempt a where a.realmId=:realm and a.accountId=:account",Object[].class)
        .setParameter("realm",realm.getId()).setParameter("account",account).setMaxResults(2).getResultList();
    if(locators.size()>1)deny();
    ProtectedInvitationConfiguration.Profile profile;String provenance;JsonNode tenant;
    if(locators.isEmpty()){
      var adoption=config.adoptedAccounts.get(account);if(adoption==null)deny();
      profile=config.profiles.get(adoption.profileId());if(profile==null||profile.version()!=adoption.profileVersion())deny();
      // A transfer cannot manufacture a fresh adoption anchor or reset its native birth.
      var historical=MaintenanceAdoption.historical(session,crypto,account,"PROTECTED",profile.id(),profile.version(),profile.snapshot());
      if(live){
        var current=MaintenanceAdoption.prepare(session,crypto,account,"PROTECTED",profile.id(),profile.version(),profile.snapshot(),historical.tenant());
        if(!current.provenance().equals(historical.provenance()))deny();
      }
      provenance=historical.provenance();tenant=historical.tenant();
    }else{
      var locator=locators.get(0);var scope=parse((String)locator[1]);
      String approvalId=uuid(text(scope.path("approvalBinding"),"approvalId",36,false));
      var approval=em.find(ProtectedInvitationApproval.class,ProtectedInvitationResource.key(realm.getId(),approvalId),LockModeType.PESSIMISTIC_WRITE);
      if(approval==null)deny();em.refresh(approval);
      var attempt=em.find(AccountLifecycleAttempt.class,locator[0],LockModeType.PESSIMISTIC_WRITE);
      if(attempt==null)deny();em.refresh(attempt);
      if(!account.equals(attempt.accountId)||!locator[1].equals(attempt.scope))deny();
      var frozen=parse(approval.scope).path("profile");profile=config.profiles.get(text(frozen,"id",255,false));
      if(profile==null||!canonical(profile.snapshot()).equals(canonical(frozen)))deny();
      long originalTenant=new ProtectedPeerDelegation(session,config,crypto).committedOperationTarget(approval,attempt,profile);
      if(live)OriginalNativeBirth.require(em,crypto,attempt);else OriginalNativeBirth.authenticated(crypto,attempt);
      provenance=attempt.id;tenant=JSON.valueToTree(Long.toString(originalTenant));
    }
    var lineage=MaintenanceLineage.resolve(session,crypto,account,provenance,"PROTECTED",profile.id(),profile.version(),tenant,profile.snapshot());
    return new Checked(lineage,"PLATFORM_ADMIN".equals(profile.kind()));
  }
  private ProtectedOrdinaryTransfer(){}
}
