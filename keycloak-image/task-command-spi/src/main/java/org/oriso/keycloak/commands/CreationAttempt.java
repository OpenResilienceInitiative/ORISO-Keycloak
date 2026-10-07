package org.oriso.keycloak.commands;

import jakarta.persistence.*;

/** Persistent ownership and terminal tombstone, committed with the identity mutation. */
@Entity
@Table(name = "ORISO_CREATION_ATTEMPT")
public class CreationAttempt {
  @Id
  @Column(name = "ID", length = 100)
  public String id;

  @Column(name = "REALM_ID", length = 36, nullable = false)
  public String realmId;

  @Column(name = "ATTEMPT_ID", length = 36, nullable = false)
  public String attemptId;

  @Column(name = "OWNER_SUBJECT", length = 255, nullable = false)
  public String ownerSubject;

  @Column(name = "OWNER_CLIENT", length = 255, nullable = false)
  public String ownerClient;

  @Column(name = "REGISTRATION_KIND", length = 30, nullable = false)
  public String registrationKind;

  @Column(name = "ORIGIN_KIND", length = 30)
  public String originKind;

  @Column(name = "INITIAL_ROLES", length = 500)
  public String initialRoles;

  @Column(name = "ACCOUNT_ID", length = 255)
  public String accountId;

  @Column(name = "TENANT_ID", length = 40)
  public String tenantId;

  @Column(name = "FINGERPRINT", length = 64, nullable = false)
  public String fingerprint;

  @Column(name = "STATUS", length = 20, nullable = false)
  public String status;

  @Version
  @Column(name = "VERSION")
  public long version;
}
