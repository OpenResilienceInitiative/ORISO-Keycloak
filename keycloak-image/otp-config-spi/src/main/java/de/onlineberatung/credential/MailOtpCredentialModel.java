package de.onlineberatung.credential;

import static org.keycloak.util.JsonSerialization.writeValueAsString;

import de.onlineberatung.otp.Otp;
import java.io.IOException;
import java.time.Clock;
import org.jetbrains.annotations.NotNull;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

public class MailOtpCredentialModel extends CredentialModel {

  public static final String TYPE = "MAIL_OTP_CM";
  public static final String INVALIDATED = "INVALIDATED";

  private final MailOtpCredentialData credentialData;
  private final MailOtpSecretData secretData;

  public static MailOtpCredentialModel createFromCredentialModel(CredentialModel credentialModel) {
    try {
      var credentialData = JsonSerialization.readValue(credentialModel.getCredentialData(),
          MailOtpCredentialData.class);
      var secretData = JsonSerialization.readValue(credentialModel.getSecretData(),
          MailOtpSecretData.class);
      var otpCredentialModel = new MailOtpCredentialModel(credentialData, secretData);
      otpCredentialModel.setUserLabel(credentialModel.getUserLabel());
      otpCredentialModel.setCreatedDate(credentialModel.getCreatedDate());
      otpCredentialModel.setType(TYPE);
      otpCredentialModel.setId(credentialModel.getId());
      return otpCredentialModel;
    } catch (IOException e) {
      throw new RuntimeException("failed to create from credential model", e);
    }
  }

  public static MailOtpCredentialModel createOtpModel(Otp otp, Clock clock) {
    var credentialModel = new MailOtpCredentialModel(otp.getCode(), otp.getTtlInSeconds(),
        otp.getExpiry(), otp.getEmail(), otp.getFailedVerifications(), false);
    return serialize(clock, credentialModel);
  }

  public static MailOtpCredentialModel createOtpModel(Otp otp, Clock clock, boolean active) {
    var credentialModel = new MailOtpCredentialModel(otp.getCode(), otp.getTtlInSeconds(),
        otp.getExpiry(), otp.getEmail(), otp.getFailedVerifications(), active);
    return serialize(clock, credentialModel);
  }

  @NotNull
  private static MailOtpCredentialModel serialize(Clock clock,
      MailOtpCredentialModel credentialModel) {
    credentialModel.setType(TYPE);
    credentialModel.setCreatedDate(clock.millis());
    credentialModel.updateInternalModel();
    return credentialModel;
  }

  private MailOtpCredentialModel(String code, long ttlInSeconds, long expiry, String email,
      int failedVerifications, boolean active) {
    this.credentialData = new MailOtpCredentialData(ttlInSeconds, email,
        failedVerifications, active);
    this.secretData = new MailOtpSecretData(code, expiry);
  }

  private MailOtpCredentialModel(MailOtpCredentialData credentialData,
      MailOtpSecretData secretData) {
    this.credentialData = credentialData;
    this.secretData = secretData;
  }

  public Otp getOtp() {
    return new Otp(secretData.getCode(), credentialData.getTtlInSeconds(),
        secretData.getExpiry(), credentialData.getEmail(),
        credentialData.getFailedVerifications()
    );
  }

  public MailOtpCredentialModel updateFrom(Otp otp) {
    credentialData.setEmail(otp.getEmail());
    credentialData.setFailedVerifications(otp.getFailedVerifications());
    credentialData.setTtlInSeconds(otp.getTtlInSeconds());

    secretData.setExpiry(otp.getExpiry());
    secretData.setCode(otp.getCode());

    updateInternalModel();
    return this;
  }

  public boolean isActive() {
    return credentialData.isActive();
  }

  void updateFailedVerifications(int failedVerifications) {
    this.credentialData.setFailedVerifications(failedVerifications);
  }

  void setActive() {
    this.credentialData.setActive(true);
  }

  void invalidateCode() {
    this.secretData.setCode(INVALIDATED);
  }

  void updateInternalModel() {
    try {
      setCredentialData(writeValueAsString(credentialData));
      setSecretData(writeValueAsString(secretData));
    } catch (IOException e) {
      throw new RuntimeException("failed to update internal model", e);
    }
  }
}
