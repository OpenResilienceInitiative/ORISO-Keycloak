package de.onlineberatung.otp;

import java.util.Objects;

public class Otp {

  private final String code;
  private final long ttlInSeconds;
  private final long expiry;
  private final String email;
  private final int failedVerifications;

  public Otp(String code, long ttlInSeconds, long expiry, String email, int failedVerifications) {
    this.code = code;
    this.ttlInSeconds = ttlInSeconds;
    this.expiry = expiry;
    this.email = email;
    this.failedVerifications = failedVerifications;
  }

  public String getCode() {
    return code;
  }

  public long getTtlInSeconds() {
    return ttlInSeconds;
  }

  public long getExpiry() {
    return expiry;
  }

  public String getEmail() {
    return email;
  }

  public int getFailedVerifications() {
    return failedVerifications;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    Otp otp = (Otp) o;
    return ttlInSeconds == otp.ttlInSeconds && expiry == otp.expiry
        && failedVerifications == otp.failedVerifications && Objects.equals(code, otp.code)
        && Objects.equals(email, otp.email);
  }

  @Override
  public int hashCode() {
    return Objects.hash(code, ttlInSeconds, expiry, email, failedVerifications);
  }

  @Override
  public String toString() {
    return "Otp{" +
        "code='" + code + '\'' +
        ", ttlInSeconds=" + ttlInSeconds +
        ", expiry=" + expiry +
        ", email='" + email + '\'' +
        ", failedVerifications=" + failedVerifications +
        '}';
  }
}
