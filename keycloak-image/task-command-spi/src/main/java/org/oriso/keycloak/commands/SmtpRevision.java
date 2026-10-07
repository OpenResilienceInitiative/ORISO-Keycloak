package org.oriso.keycloak.commands;

import jakarta.persistence.*;

@Entity
@Table(name = "ORISO_SMTP_REVISION")
public class SmtpRevision {
  @Id
  @Column(name = "REALM_ID", length = 36)
  public String realmId;

  @Column(name = "REVISION", nullable = false)
  public long revision;

  @Column(name = "FINGERPRINT", length = 64, nullable = false)
  public String fingerprint;

  @Version
  @Column(name = "VERSION")
  public long version;
}
