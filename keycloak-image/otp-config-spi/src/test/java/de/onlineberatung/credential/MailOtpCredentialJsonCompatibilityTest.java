package de.onlineberatung.credential;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import org.junit.Test;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

/**
 * The stored e-mail-2FA credential is JSON, and reading it is not optional: {@code
 * createFromCredentialModel} turns a deserialization error into a RuntimeException, which means the
 * owner cannot log in at all.
 *
 * <p>Measured on 2026-10-02, before #1338: an unknown field made Jackson throw
 * UnrecognizedPropertyException. So a credential written by a NEWER build locked its owner out after
 * an image rollback. These tests pin both directions of that compatibility.
 */
public class MailOtpCredentialJsonCompatibilityTest {

  @Test
  public void credentialData_written_by_a_newer_build_is_still_readable() throws Exception {
    var json = "{\"ttlInSeconds\":900,\"email\":\"a@b.de\",\"failedVerifications\":1,"
        + "\"active\":true,\"somethingAddedLater\":123}";

    var data = JsonSerialization.readValue(json, MailOtpCredentialData.class);

    assertThat(data.getEmail()).isEqualTo("a@b.de");
    assertThat(data.getFailedVerifications()).isEqualTo(1);
    assertThat(data.isActive()).isTrue();
  }

  @Test
  public void secretData_written_by_a_newer_build_is_still_readable() throws Exception {
    var json = "{\"code\":\"123456\",\"expiry\":42,\"somethingAddedLater\":\"x\"}";

    var data = JsonSerialization.readValue(json, MailOtpSecretData.class);

    assertThat(data.getCode()).isEqualTo("123456");
    assertThat(data.getExpiry()).isEqualTo(42L);
  }

  @Test
  public void a_credential_stored_before_1338_reads_as_never_having_sent_a_mail() throws Exception {
    // the row has no send bookkeeping at all; it must be allowed one mail rather than be stuck
    var stored = new CredentialModel();
    stored.setType(MailOtpCredentialModel.TYPE);
    stored.setCredentialData(
        "{\"ttlInSeconds\":900,\"email\":\"a@b.de\",\"failedVerifications\":0,\"active\":true}");
    stored.setSecretData("{\"code\":\"123456\",\"expiry\":42}");
    stored.setCreatedDate(Clock.systemDefaultZone().millis());

    var model = MailOtpCredentialModel.createFromCredentialModel(stored);

    assertThat(model.getLastMailSentAt()).isZero();
    assertThat(model.getSendWindowStartedAt()).isZero();
    assertThat(model.getMailsSentInWindow()).isZero();
    assertThat(model.isActive()).isTrue();
  }

  @Test
  public void send_bookkeeping_survives_a_write_and_read_round_trip() throws Exception {
    var model = MailOtpCredentialModel.createOtpModel(
        new de.onlineberatung.otp.Otp("123456", 900, 1000L, "a@b.de", 0),
        Clock.systemDefaultZone(), true);
    model.applySendBookkeeping(1_700_000_000_000L, 1_699_999_000_000L, 3);

    var stored = new CredentialModel();
    stored.setType(MailOtpCredentialModel.TYPE);
    stored.setCredentialData(model.getCredentialData());
    stored.setSecretData(model.getSecretData());
    var reloaded = MailOtpCredentialModel.createFromCredentialModel(stored);

    assertThat(reloaded.getLastMailSentAt()).isEqualTo(1_700_000_000_000L);
    assertThat(reloaded.getSendWindowStartedAt()).isEqualTo(1_699_999_000_000L);
    assertThat(reloaded.getMailsSentInWindow()).isEqualTo(3);
  }
}
