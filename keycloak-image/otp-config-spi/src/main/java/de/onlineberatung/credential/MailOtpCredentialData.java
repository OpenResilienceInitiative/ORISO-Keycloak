package de.onlineberatung.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * The non-secret part of the e-mail OTP credential, stored as JSON in Keycloak's database.
 *
 * <p>Unknown fields are ignored so that an image can read what a newer image wrote; without it a
 * rollback would break the login of everyone whose credential was written in between.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class MailOtpCredentialData {

  private long ttlInSeconds;
  private String email;
  private int failedVerifications;
  private boolean active;
  /** When the last code mails went out (epoch millis), for the resend cooldown and cap. */
  private List<Long> mailsSentAt;
  /** When the failed-attempt lockout ends (epoch millis); null for a credential never locked. */
  private Long lockedUntil;
  /** Which step of the lockout ladder the last lockout was; 0 when there was none. */
  private int lockoutLevel;

  // for json de/serialization
  public MailOtpCredentialData() {
  }

  public MailOtpCredentialData(long ttlInSeconds, String email,
      int failedVerifications, boolean active) {
    this.ttlInSeconds = ttlInSeconds;
    this.email = email;
    this.failedVerifications = failedVerifications;
    this.active = active;
  }

  public long getTtlInSeconds() {
    return ttlInSeconds;
  }

  public void setTtlInSeconds(long ttlInSeconds) {
    this.ttlInSeconds = ttlInSeconds;
  }

  public String getEmail() {
    return email;
  }

  public void setEmail(String email) {
    this.email = email;
  }

  public int getFailedVerifications() {
    return failedVerifications;
  }

  public boolean isActive() {
    return active;
  }

  public void setActive(boolean active) {
    this.active = active;
  }

  public void setFailedVerifications(int failedVerifications) {
    this.failedVerifications = failedVerifications;
  }

  public List<Long> getMailsSentAt() {
    return mailsSentAt;
  }

  public void setMailsSentAt(List<Long> mailsSentAt) {
    this.mailsSentAt = mailsSentAt;
  }

  public Long getLockedUntil() {
    return lockedUntil;
  }

  public void setLockedUntil(Long lockedUntil) {
    this.lockedUntil = lockedUntil;
  }

  public int getLockoutLevel() {
    return lockoutLevel;
  }

  public void setLockoutLevel(int lockoutLevel) {
    this.lockoutLevel = lockoutLevel;
  }
}
