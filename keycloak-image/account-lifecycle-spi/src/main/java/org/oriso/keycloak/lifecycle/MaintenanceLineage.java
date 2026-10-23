package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import java.util.Base64;
import org.keycloak.models.KeycloakSession;

/** MAC-bound append-only transitions preserve the original committed creation/adoption. */
final class MaintenanceLineage {
  record Current(String kind, String profileId, long profileVersion, JsonNode tenant,
      String digest, long sequence, String provenance, JsonNode nativeProfile) {}

  static Current resolve(KeycloakSession session, LifecycleAuthorization crypto, String account,
      String provenance, String kind, String profileId, long version, JsonNode tenant, JsonNode nativeProfile) {
    var em = CurrentNativeHumanIdentity.entityManager(session);
    var realm = session.getContext().getRealm().getId();
    var rows = em.createQuery("select l from AccountMaintenanceLineage l where l.realmId=:realm"
        + " and l.accountId=:account order by l.sequence", AccountMaintenanceLineage.class)
        .setParameter("realm", realm).setParameter("account", account)
        .setLockMode(LockModeType.PESSIMISTIC_WRITE).setMaxResults(10001).getResultList();
    if (rows.size() > 10000) deny();
    var current = new Current(kind, profileId, version, tenant.deepCopy(), null, 0, provenance, nativeProfile.deepCopy());
    for (var row : rows) {
      em.refresh(row);
      var value = parse(row.snapshotJson);
      var closed=value.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)closed).remove("roleChange");
      fields(closed, "v", "realmId", "accountId", "provenanceDigest", "sequence", "previousLineageDigest",
          "operationId", "command", "intentDigest", "previousState", "from", "desired");
      if (number(value, "v", true) != 1 || !realm.equals(row.realmId) || !account.equals(row.accountId)
          || !realm.equals(value.path("realmId").asText()) || !account.equals(value.path("accountId").asText())
          || !provenance.equals(value.path("provenanceDigest").asText())
          || row.sequence != current.sequence + 1 || number(value, "sequence", true) != row.sequence
          || !row.operationId.equals(value.path("operationId").asText())
          || !java.util.Objects.equals(current.digest, text(value, "previousLineageDigest", 64, true))
          || !canonical(binding(current)).equals(canonical(value.path("from")))
          || !LifecycleAuthorization.equal(crypto.mac("maintenance-lineage/v1", value), row.lineageDigest)) deny();
      var desired = value.path("desired");
      fields(desired, "profileKind", "profileId", "profileVersion", "tenantId", "nativeProfile");
      String nextKind = text(desired, "profileKind", 20, false);
      String nextId = text(desired, "profileId", 255, false);
      long nextVersion = number(desired, "profileVersion", true);
      String command = text(value, "command", 40, false);
      if(!current.kind.equals(nextKind))deny();
      if(value.has("roleChange")){
        var capsule=value.path("roleChange");
        if(!current.tenant.equals(desired.path("tenantId"))
            ||!("profile-transition".equals(command)&&!"IMPORT".equals(capsule.path("kind").asText())
                ||"ordinary-profile".equals(command)&&"ORDINARY".equals(nextKind)&&"IMPORT".equals(capsule.path("kind").asText())))deny();
        MaintenanceRoleChange.require(capsule,nextKind,current.nativeProfile,desired.path("nativeProfile"));
      }else if("ordinary-profile".equals(command)&&"ORDINARY".equals(nextKind)){
        var before=HumanPolicyJson.strings(current.nativeProfile.path("realmRoles"),1,10,255);
        var after=HumanPolicyJson.strings(desired.path("nativeProfile").path("realmRoles"),1,10,255);
        if(!current.tenant.equals(desired.path("tenantId"))||!java.util.Objects.equals(LifecycleGroups.allowedKind(before),LifecycleGroups.allowedKind(after))
            ||!canonical(current.nativeProfile.path("clientRoles")).equals(canonical(desired.path("nativeProfile").path("clientRoles"))))deny();
      }else if(!("reassign-tenant".equals(command)&&"PROTECTED".equals(nextKind)&&current.profileId.equals(nextId)
          &&current.profileVersion==nextVersion&&positiveTenant(current.tenant)&&positiveTenant(desired.path("tenantId"))
          &&canonical(current.nativeProfile).equals(canonical(desired.path("nativeProfile")))))deny();
      var operation = em.find(AccountMaintenanceOperation.class, row.id, LockModeType.PESSIMISTIC_WRITE);
      if (operation == null) deny();
      em.refresh(operation);
      var result = parse(operation.resultJson);
      fields(result, "operationId", "accountId", "result", "receipt");
      String saved = text(result, "receipt", 16000, false);
      String[] pieces = saved.split("\\.", -1);
      if (pieces.length != 2) deny();
      JsonNode receipt;
      try { receipt = parse(Base64.getUrlDecoder().decode(pieces[0])); }
      catch (IllegalArgumentException malformed) { deny(); return null; }
      fields(receipt, "realmId", "accountId", "operationId", "command", "ownerClient", "ownerSubject",
          "intentDigest", "previousState", "tenantId", "originDigest", "result");
      if (!realm.equals(operation.realmId) || !account.equals(operation.accountId)
          || !row.operationId.equals(operation.operationId) || !command.equals(operation.command)
          || !"backend-account-admin".equals(operation.ownerClient) || !crypto.adminSubject.equals(operation.ownerSubject)
          || !operation.intentDigest.equals(value.path("intentDigest").asText())
          || !operation.expectedState.equals(value.path("previousState").asText())
          || !realm.equals(receipt.path("realmId").asText()) || !account.equals(receipt.path("accountId").asText())
          || !row.operationId.equals(receipt.path("operationId").asText()) || !command.equals(receipt.path("command").asText())
          || !operation.ownerClient.equals(receipt.path("ownerClient").asText())
          || !operation.ownerSubject.equals(receipt.path("ownerSubject").asText())
          || !operation.intentDigest.equals(receipt.path("intentDigest").asText())
          || !operation.expectedState.equals(receipt.path("previousState").asText())
          || !current.tenant.equals(receipt.path("tenantId")) || !"UPDATED".equals(receipt.path("result").asText())
          || !row.operationId.equals(result.path("operationId").asText()) || !account.equals(result.path("accountId").asText())
          || !"UPDATED".equals(result.path("result").asText())
          || !LifecycleAuthorization.equal(crypto.receipt("maintenance-operation-receipt", receipt), saved)) deny();
      current = new Current(nextKind, nextId, nextVersion, desired.path("tenantId").deepCopy(),
          row.lineageDigest, row.sequence, provenance, desired.path("nativeProfile").deepCopy());
    }
    return current;
  }

  static void append(KeycloakSession session, LifecycleAuthorization crypto, MaintenanceRequest request,
      JsonNode body, Current current, String profileId, long version, JsonNode tenant, JsonNode nativeProfile) {
    if (current.sequence >= 10000) deny();
    var realm = session.getContext().getRealm().getId();
    var value = JSON.createObjectNode(); value.put("v", 1); value.put("realmId", realm);
    value.put("accountId", request.accountId()); value.put("provenanceDigest", current.provenance);
    value.put("sequence", current.sequence + 1); value.put("previousLineageDigest", current.digest);
    value.put("operationId", request.operationId()); value.put("command", request.command());
    value.put("intentDigest", crypto.mac("maintenance-intent", body)); value.put("previousState", request.expectedState());
    var roleChange=MaintenanceRoleChange.capsule(request);if(roleChange!=null)value.set("roleChange",roleChange);
    value.set("from", binding(current));
    value.set("desired", binding(new Current(current.kind, profileId, version, tenant, null, 0, current.provenance, nativeProfile)));
    var row = new AccountMaintenanceLineage(); row.id = realm + ":" + request.operationId();
    row.realmId = realm; row.accountId = request.accountId(); row.sequence = current.sequence + 1;
    row.operationId = request.operationId(); row.snapshotJson = canonical(value);
    if(row.snapshotJson.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>65536)throw MaintenancePreflightRefusal.current(403);
    row.lineageDigest = crypto.mac("maintenance-lineage/v1", value);
    CurrentNativeHumanIdentity.entityManager(session).persist(row);
  }

  static Current ordinaryExisting(KeycloakSession session,LifecycleAuthorization crypto,String account,String provenance,
      String originalPath,String originalGroup,java.util.Set<String> originalRoles,JsonNode tenant) {
    var em=CurrentNativeHumanIdentity.entityManager(session);
    var rows=em.createQuery("select l from AccountMaintenanceLineage l where l.realmId=:realm and l.accountId=:account order by l.sequence",AccountMaintenanceLineage.class)
        .setParameter("realm",session.getContext().getRealm().getId()).setParameter("account",account).setLockMode(LockModeType.PESSIMISTIC_WRITE).setMaxResults(1).getResultList();
    if(rows.isEmpty())return null;
    var first=rows.get(0);em.refresh(first);var value=parse(first.snapshotJson);var from=value.path("from");var profile=from.path("nativeProfile");
    var roles=HumanPolicyJson.strings(profile.path("realmRoles"),1,10,255);
    if(!"ORDINARY".equals(from.path("profileKind").asText())||!originalPath.equals(profile.path("groupPath").asText())
        ||!originalGroup.equals(profile.path("groupId").asText())||!roles.equals(originalRoles)||!profile.path("clientRoles").isObject()
        ||!profile.path("clientRoles").isEmpty())deny();
    return resolve(session,crypto,account,provenance,"ORDINARY",text(from,"profileId",100,false),number(from,"profileVersion",true),tenant,profile);
  }

  private static JsonNode binding(Current current) {
    var result = JSON.createObjectNode(); result.put("profileKind", current.kind);
    result.put("profileId", current.profileId); result.put("profileVersion", current.profileVersion);
    result.set("tenantId", current.tenant); result.set("nativeProfile", current.nativeProfile); return result;
  }
  private static boolean positiveTenant(JsonNode tenant) {
    return tenant.isTextual() && tenant.asText().matches("[1-9][0-9]{0,18}");
  }
  private MaintenanceLineage() {}
}
