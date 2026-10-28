package org.oriso.keycloak.lifecycle;

import static org.junit.Assert.*;
import org.junit.Test;

public class OriginalNativeBirthTest {
  private final LifecycleAuthorization crypto = new LifecycleAuthorization("realm", "creator", "admin",
      new byte[32], java.util.Base64.getEncoder().encodeToString(new byte[32]));
  private AccountLifecycleAttempt row() {
    var row = new AccountLifecycleAttempt();
    row.realmId="realm-id";row.attemptId="attempt";row.accountId="account";
    row.ownerClient="backend-account-create";row.ownerSubject="creator";
    row.scope="{\"tenantId\":\"1\"}";row.creationFingerprint="c";row.groupId="g";row.roleFingerprint="r";
    return row;
  }
  @Test public void originalCapsuleAuthenticatesEveryCreationBindingAndPositiveBirth() {
    var row=row();row.originalNativeJson=OriginalNativeBirth.seal(crypto,row,1234);
    assertEquals(1234,OriginalNativeBirth.authenticated(crypto,row));
    row.accountId="replacement";
    assertThrows(jakarta.ws.rs.ForbiddenException.class,()->OriginalNativeBirth.authenticated(crypto,row));
  }
  @Test public void absentCorruptAndChangedBirthNeverAcquireProvenance() {
    var row=row();
    assertThrows(jakarta.ws.rs.ForbiddenException.class,()->OriginalNativeBirth.authenticated(crypto,row));
    row.originalNativeJson=OriginalNativeBirth.seal(crypto,row,1234).replace("1234","1235");
    assertThrows(jakarta.ws.rs.ForbiddenException.class,()->OriginalNativeBirth.authenticated(crypto,row));
    assertThrows(jakarta.ws.rs.ForbiddenException.class,()->OriginalNativeBirth.seal(crypto,row,0));
    row.originalNativeJson="{}";
    assertThrows(jakarta.ws.rs.ForbiddenException.class,()->OriginalNativeBirth.authenticated(crypto,row));
  }
}
