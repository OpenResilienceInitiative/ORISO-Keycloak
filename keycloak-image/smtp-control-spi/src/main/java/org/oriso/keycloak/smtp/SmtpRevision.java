package org.oriso.keycloak.smtp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

@Entity
@Table(name = "ORISO_SMTP_CONTROL_REVISION")
public class SmtpRevision {
  @Id @Column(name = "REALM_ID", length = 255)
  public String realmId;
  @Column(name = "REVISION", nullable = false)
  public long revision;
  @Column(name = "FINGERPRINT", length = 64, nullable = false)
  public String fingerprint;
  @Column(name = "STATUS", length = 30, nullable = false)
  public String status;
  @Version @Column(name = "VERSION")
  public long version;
}
