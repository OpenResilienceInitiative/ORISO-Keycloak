package org.oriso.keycloak.lifecycle;

import jakarta.persistence.*;

/** Receiver-owned pending bootstrap phase. No address, setup material, code or bearer. */
@Entity
@Table(name = "ORISO_PROTECTED_OTP_BOOTSTRAP")
public class ProtectedOtpBootstrapState {
  @Id @Column(name = "ID", length = 100) String id;
  @Column(name = "REALM_ID", length = 255, nullable = false, updatable = false) String realmId;
  @Column(name = "APPROVAL_ID", length = 36, nullable = false, updatable = false) String approvalId;
  @Column(name = "ATTEMPT_ID", length = 36, nullable = false, updatable = false) String attemptId;
  @Column(name = "ACCOUNT_ID", length = 255, nullable = false, updatable = false) String accountId;
  @Column(name = "CLAIM_ID", length = 36, nullable = false, updatable = false) String claimId;
  @Column(name = "EXECUTION_ID", length = 36, nullable = false, updatable = false) String executionId;
  @Column(name = "OWNER_CLIENT", length = 255, nullable = false, updatable = false) String ownerClient;
  @Column(name = "OWNER_SUBJECT", length = 255, nullable = false, updatable = false) String ownerSubject;
  @Column(name = "ORIGIN_DIGEST", length = 64, nullable = false, updatable = false) String originDigest;
  @Column(name = "AUTHORITY_VALID_UNTIL", nullable = false, updatable = false) long authorityValidUntil;
  @Column(name = "STATE", length = 20, nullable = false) String state;
  @Column(name = "PREPARE_RECEIPT", length = 8192, nullable = false, updatable = false) String prepareReceipt;
  @Column(name = "EMAIL_PENDING_FINGERPRINT", length = 64) String emailPendingFingerprint;
  @Version @Column(name = "VERSION", nullable = false) long version;
  protected ProtectedOtpBootstrapState() {}
}
