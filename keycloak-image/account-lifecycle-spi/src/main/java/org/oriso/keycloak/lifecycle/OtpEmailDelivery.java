package org.oriso.keycloak.lifecycle;

import jakarta.persistence.*;

/** Private native-owned delivery state. No recipient, code, JWT or bearer-derived grant is stored. */
@Entity
@Table(name = "ORISO_OTP_EMAIL_DELIVERY")
public class OtpEmailDelivery {
  @Id @Column(name = "ID", length = 255) String id;
  @Column(name = "REALM_ID", length = 255, nullable = false, updatable = false) String realmId;
  @Column(name = "ACCOUNT_ID", length = 255, nullable = false, updatable = false) String accountId;
  @Column(name = "INTENT_DIGEST", length = 64, nullable = false, updatable = false) String intentDigest;
  @Column(name = "BINDING_JSON", length = 1024, nullable = false, updatable = false) String bindingJson;
  @Column(name = "EXPIRES_AT", nullable = false, updatable = false) long expiresAt;
  @Column(name = "STATE", length = 16, nullable = false) String state;
  @Column(name = "FINAL_JSON", length = 16000) String finalJson;
  @Version @Column(name = "VERSION", nullable = false) long version;
  protected OtpEmailDelivery() {}
}
