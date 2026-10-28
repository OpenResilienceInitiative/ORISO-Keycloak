package de.onlineberatung.credential;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import de.onlineberatung.otp.Otp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.Test;

public class MailOtpCredentialModelTest {

  @Test
  public void nativeProviderRoundtripRetainsTheSerializedPendingCredential() {
    var clock = Clock.fixed(Instant.parse("2026-10-21T10:00:00Z"), ZoneOffset.UTC);
    var pending = MailOtpCredentialModel.createOtpModel(
        new Otp("937451", 600, clock.millis() + 600000, "pending@fixture.invalid", 0), clock);
    pending.setId("11111111-1111-4111-8111-111111111111");
    pending.setUserLabel("fixture pending mail");
    assertNotNull(pending.getCredentialData());
    assertNotNull(pending.getSecretData());

    // Keycloak's real createCredentialThroughProvider converts the generic model before create.
    var converted = MailOtpCredentialModel.createFromCredentialModel(pending);
    assertEquals(pending.getCredentialData(), converted.getCredentialData());
    assertEquals(pending.getSecretData(), converted.getSecretData());
    assertEquals(pending.getId(), converted.getId());
    assertEquals(pending.getCreatedDate(), converted.getCreatedDate());
    assertEquals(pending.getUserLabel(), converted.getUserLabel());
    assertEquals(pending.getOtp(), converted.getOtp());
  }
}
