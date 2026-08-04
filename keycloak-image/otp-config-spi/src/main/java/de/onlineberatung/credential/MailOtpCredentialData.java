package de.onlineberatung.credential;

public class MailOtpCredentialData {

  private long ttlInSeconds;
  private String email;
  private int failedVerifications;
  private boolean active;

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
}
