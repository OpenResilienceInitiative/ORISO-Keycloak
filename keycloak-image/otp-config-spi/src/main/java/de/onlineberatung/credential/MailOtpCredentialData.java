package de.onlineberatung.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Measured on 2026-10-02: without this annotation Keycloak's JsonSerialization throws
 * UnrecognizedPropertyException on a field it does not know, and createFromCredentialModel
 * turns that into a RuntimeException — so every e-mail second factor written by a NEWER build
 * would lock its owner out after an image rollback. Tolerating unknown fields makes that
 * rollback survivable from this release onwards.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class MailOtpCredentialData {

  private long ttlInSeconds;
  private String email;
  private int failedVerifications;
  private boolean active;

  // Send bookkeeping for the cooldown and the per-window cap (#1338). Stored with the credential
  // rather than held in memory so both limits survive a restart and hold across replicas. Rows
  // written before #1338 deserialize these as 0, which reads as "never sent" and allows one mail.
  private long lastMailSentAt;
  private long sendWindowStartedAt;
  private int mailsSentInWindow;

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

  public long getLastMailSentAt() {
    return lastMailSentAt;
  }

  public void setLastMailSentAt(long lastMailSentAt) {
    this.lastMailSentAt = lastMailSentAt;
  }

  public long getSendWindowStartedAt() {
    return sendWindowStartedAt;
  }

  public void setSendWindowStartedAt(long sendWindowStartedAt) {
    this.sendWindowStartedAt = sendWindowStartedAt;
  }

  public int getMailsSentInWindow() {
    return mailsSentInWindow;
  }

  public void setMailsSentInWindow(int mailsSentInWindow) {
    this.mailsSentInWindow = mailsSentInWindow;
  }
}
