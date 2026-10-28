package org.oriso.keycloak.lifecycle;

import static org.junit.Assert.*;
import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import org.junit.Test;

public class InstallationStatusTest {
  @Test public void loadedPolicyFingerprintIgnoresObjectOrderButDetectsGrantChanges() {
    assertEquals(InstallationStatus.fingerprint(parse("{\"version\":1,\"roles\":[\"consultant\"]}")),
        InstallationStatus.fingerprint(parse("{\"roles\":[\"consultant\"],\"version\":1}")));
    assertNotEquals(InstallationStatus.fingerprint(parse("{\"roles\":[\"consultant\"]}")),
        InstallationStatus.fingerprint(parse("{\"roles\":[\"consultant\",\"user-admin\"]}")));
  }
  @Test public void unpackagedClassesCannotClaimAnInstalledJarDigest() {
    assertThrows(jakarta.ws.rs.ServiceUnavailableException.class,
        () -> InstallationStatus.jarFingerprint(InstallationStatusTest.class));
  }
}
