package org.oriso.keycloak.lifecycle;

import jakarta.persistence.*;

/** Receiver-owned provenance, transactionally committed with the local identity. */
@Entity
@Table(
    name = "ORISO_ACCOUNT_LIFECYCLE_ATTEMPT",
    uniqueConstraints = @UniqueConstraint(columnNames = "ACCOUNT_ID"))
public class AccountLifecycleAttempt {
  // Native realm IDs plus the attempt UUID fit255; MariaDB keys must stay VARCHAR.
  @Id
  @Column(name = "ID", length = 255)
  String id;

  @Column(name = "REALM_ID", length = 255, nullable = false, updatable = false)
  String realmId;

  @Column(name = "ATTEMPT_ID", length = 36, nullable = false, updatable = false)
  String attemptId;

  @Column(name = "OWNER_CLIENT", length = 255, nullable = false, updatable = false)
  String ownerClient;

  @Column(name = "OWNER_SUBJECT", length = 255, nullable = false, updatable = false)
  String ownerSubject;

  @Column(name = "SCOPE_JSON", length = 16000, nullable = false, updatable = false)
  String scope;

  @Column(name = "GROUP_ID", length = 255, nullable = false, updatable = false)
  String groupId;

  @Column(name = "ROLE_FINGERPRINT", length = 64, nullable = false, updatable = false)
  String roleFingerprint;

  @Column(name = "CREATION_FINGERPRINT", length = 64, nullable = false, updatable = false)
  String creationFingerprint;

  @Column(name = "CREATE_EXECUTION", length = 36, updatable = false)
  String createExecution;

  @Column(name = "ACCOUNT_ID", length = 255)
  String accountId;

  @Column(name = "PROFILE_FINGERPRINT", length = 64)
  String profileFingerprint;

  @Column(name = "CREATION_PROOF", length = 16384)
  String creationProof;

  @Column(name = "STATE", length = 30, nullable = false)
  String state;

  @Column(name = "GENERATION", nullable = false)
  long generation;

  @Column(name = "EXECUTION_ID", length = 36, nullable = false)
  String executionId;

  @Column(name = "RECOVERY_ID", length = 36)
  String recoveryId;

  @Column(name = "RECOVERY_EXPECTED")
  Long recoveryExpected;

  @Column(name = "RECOVERY_DIGEST", length = 64)
  String recoveryDigest;

  @Column(name = "RECOVERY_RECEIPT", length = 16000)
  String recoveryReceipt;

  @Column(name = "TERMINAL_OPERATION", length = 30)
  String terminalOperation;

  @Column(name = "TERMINAL_DIGEST", length = 64)
  String terminalDigest;

  @Column(name = "TERMINAL_RECEIPT", length = 16000)
  String terminalReceipt;

  @Version
  @Column(name = "VERSION")
  long version;

  protected AccountLifecycleAttempt() {}
}
