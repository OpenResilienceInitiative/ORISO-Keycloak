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
public class MailOtpSecretData {

  private String code;
  private long expiry;

  // for json de/serialization
  public MailOtpSecretData() {
  }

  public MailOtpSecretData(String code, long expiry) {
    this.code = code;
    this.expiry = expiry;
  }

  public String getCode() {
    return code;
  }

  public void setCode(String code) {
    this.code = code;
  }


  public long getExpiry() {
    return expiry;
  }

  public void setExpiry(long expiry) {
    this.expiry = expiry;
  }
}
