package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.EntityManager;

/** One immutable original incarnation capsule on the existing creation row; never backfilled. */
final class OriginalNativeBirth {
  private static final String DOMAIN = "ordinary-creation-native-birth/v1";

  static void capture(EntityManager em, LifecycleAuthorization crypto, AccountLifecycleAttempt row) {
    if (row.originalNativeJson != null) deny();
    row.originalNativeJson = seal(crypto, row, current(em, row));
  }

  static void require(EntityManager em, LifecycleAuthorization crypto, AccountLifecycleAttempt row) {
    if (authenticated(crypto, row) != current(em, row)) deny();
  }

  private static long current(EntityManager em, AccountLifecycleAttempt row) {
    var values = em.createNativeQuery("select CREATED_TIMESTAMP from USER_ENTITY where ID=:id and REALM_ID=:realm for update")
        .setParameter("id", row.accountId).setParameter("realm", row.realmId).getResultList();
    if (values.size() != 1 || !(values.get(0) instanceof Number)) deny();
    long birth = ((Number) values.get(0)).longValue();
    if (birth <= 0) deny();
    return birth;
  }

  static String seal(LifecycleAuthorization crypto, AccountLifecycleAttempt row, long birth) {
    if (birth <= 0) deny();
    var value = JSON.createObjectNode();
    value.put("v", 1);value.put("nativeCreatedTimestamp", birth);
    value.put("mac", crypto.mac(DOMAIN, payload(row, birth)));
    return canonical(value);
  }

  static long authenticated(LifecycleAuthorization crypto, AccountLifecycleAttempt row) {
    if (row.originalNativeJson == null || row.originalNativeJson.length() > 512) deny();
    try {
      var value=parse(row.originalNativeJson);
      fields(value,"v","nativeCreatedTimestamp","mac");
      if(number(value,"v",true)!=1 || !canonical(value).equals(row.originalNativeJson)) deny();
      long birth=number(value,"nativeCreatedTimestamp",true);
      String signature=text(value,"mac",64,false);hex(signature);
      if(!LifecycleAuthorization.equal(signature,crypto.mac(DOMAIN,payload(row,birth)))) deny();
      return birth;
    } catch (jakarta.ws.rs.BadRequestException malformed) { deny();return 0; }
  }

  private static JsonNode payload(AccountLifecycleAttempt row,long birth) {
    var value=JSON.createObjectNode();value.put("v",1);value.put("realmId",row.realmId);
    value.put("attemptId",row.attemptId);value.put("accountId",row.accountId);
    value.put("ownerClient",row.ownerClient);value.put("ownerSubject",row.ownerSubject);
    value.set("scope",parse(row.scope));value.put("creationFingerprint",row.creationFingerprint);
    value.put("initialGroupId",row.groupId);value.put("initialRoleFingerprint",row.roleFingerprint);
    value.put("nativeCreatedTimestamp",birth);return value;
  }
  private OriginalNativeBirth() {}
}
