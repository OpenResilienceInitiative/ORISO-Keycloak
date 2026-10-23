package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import org.keycloak.models.KeycloakSession;

/** Configuration selects a profile. Only a positive native check may first persist its anchor. */
final class MaintenanceAdoption {
  static final class Baseline {
    private final AccountMaintenanceAdoption row;
    private final boolean fresh;
    private final JsonNode value;
    private Baseline(AccountMaintenanceAdoption row,boolean fresh,JsonNode value){this.row=row;this.fresh=fresh;this.value=value;}
    JsonNode tenant(){return value.path("originalTenantId").deepCopy();}
    String provenance(){return row.bindingMac;}
    void checked(KeycloakSession session){if(fresh)CurrentNativeHumanIdentity.entityManager(session).persist(row);}
  }
  static Baseline prepare(KeycloakSession session,LifecycleAuthorization crypto,String account,String kind,
      String profileId,long version,JsonNode profile,JsonNode requestedTenant){
    var realm=session.getContext().getRealm();var em=CurrentNativeHumanIdentity.entityManager(session);
    var times=em.createNativeQuery("select CREATED_TIMESTAMP from USER_ENTITY where ID=:account and REALM_ID=:realm for update")
        .setParameter("account",account).setParameter("realm",realm.getId()).getResultList();
    if(times.size()!=1||!(times.get(0) instanceof Number)||((Number)times.get(0)).longValue()<=0)deny();
    long created=((Number)times.get(0)).longValue();
    var key=JSON.createObjectNode();key.put("realmId",realm.getId());key.put("accountId",account);key.put("profileKind",kind);
    String id=crypto.mac("maintenance-adoption-id/v1",key);
    var row=em.find(AccountMaintenanceAdoption.class,id,LockModeType.PESSIMISTIC_WRITE);boolean fresh=row==null;
    JsonNode value;
    if(fresh){
      var current=JSON.createObjectNode();current.put("v",1);current.put("realmId",realm.getId());current.put("accountId",account);
      current.put("profileKind",kind);current.put("profileId",profileId);current.put("profileVersion",version);
      current.set("profile",profile.deepCopy());current.put("nativeCreatedTimestamp",created);current.set("originalTenantId",requestedTenant.deepCopy());
      value=current;row=new AccountMaintenanceAdoption();row.id=id;row.realmId=realm.getId();row.accountId=account;row.kind=kind;
      row.snapshotJson=canonical(value);row.bindingMac=crypto.mac("maintenance-adoption-baseline/v1",value);
    }else{
      em.refresh(row);value=parse(row.snapshotJson);
      fields(value,"v","realmId","accountId","profileKind","profileId","profileVersion","profile","nativeCreatedTimestamp","originalTenantId");
      if(!realm.getId().equals(row.realmId)||!account.equals(row.accountId)||!kind.equals(row.kind)
          ||number(value,"v",true)!=1||!realm.getId().equals(value.path("realmId").asText())||!account.equals(value.path("accountId").asText())
          ||!kind.equals(value.path("profileKind").asText())||!profileId.equals(value.path("profileId").asText())
          ||version!=number(value,"profileVersion",true)||created!=number(value,"nativeCreatedTimestamp",true)
          ||!canonical(profile).equals(canonical(value.path("profile")))
          ||!LifecycleAuthorization.equal(crypto.mac("maintenance-adoption-baseline/v1",value),row.bindingMac))deny();
    }
    return new Baseline(row,fresh,value);
  }
  /** Historical facts only, usable after an independently verified owned native deletion tombstone. */
  static Baseline historical(KeycloakSession session,LifecycleAuthorization crypto,String account,String kind,
      String profileId,long version,JsonNode profile){
    String realm=session.getContext().getRealm().getId();var em=CurrentNativeHumanIdentity.entityManager(session);
    var key=JSON.createObjectNode();key.put("realmId",realm);key.put("accountId",account);key.put("profileKind",kind);
    var row=em.find(AccountMaintenanceAdoption.class,crypto.mac("maintenance-adoption-id/v1",key),LockModeType.PESSIMISTIC_WRITE);
    if(row==null)deny();em.refresh(row);var value=parse(row.snapshotJson);
    fields(value,"v","realmId","accountId","profileKind","profileId","profileVersion","profile","nativeCreatedTimestamp","originalTenantId");
    if(!realm.equals(row.realmId)||!account.equals(row.accountId)||!kind.equals(row.kind)||number(value,"v",true)!=1
        ||!realm.equals(value.path("realmId").asText())||!account.equals(value.path("accountId").asText())
        ||!kind.equals(value.path("profileKind").asText())||!profileId.equals(value.path("profileId").asText())
        ||version!=number(value,"profileVersion",true)||number(value,"nativeCreatedTimestamp",true)<=0
        ||!canonical(profile).equals(canonical(value.path("profile")))
        ||!LifecycleAuthorization.equal(crypto.mac("maintenance-adoption-baseline/v1",value),row.bindingMac))deny();
    return new Baseline(row,false,value);
  }
  private MaintenanceAdoption(){}
}
