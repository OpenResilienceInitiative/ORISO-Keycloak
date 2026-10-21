package org.oriso.keycloak.lifecycle;

import jakarta.persistence.*;

/** Immutable human issuance plus receiver-owned state, in the native request transaction. */
@Entity
@Table(name = "ORISO_PROTECTED_INVITATION_APPROVAL", uniqueConstraints = {
    @UniqueConstraint(columnNames = {"REALM_ID", "WORKFLOW_ID", "INVITE_ID", "AUTHORIZATION_REVISION"}),
    @UniqueConstraint(columnNames = {"REALM_ID", "DELEGATED_SUBJECT"})})
public class ProtectedInvitationApproval {
  @Id @Column(name = "ID", length = 100) String id;
  @Column(name = "REALM_ID", length = 255, nullable = false, updatable = false) String realmId;
  @Column(name = "APPROVAL_ID", length = 36, nullable = false, updatable = false) String approvalId;
  @Column(name = "WORKFLOW_ID", length = 36, nullable = false, updatable = false) String workflowId;
  @Column(name = "INVITE_ID", length = 255, nullable = false, updatable = false) String inviteId;
  @Column(name = "AUTHORIZATION_REVISION", nullable = false, updatable = false) long authorizationRevision;
  @Column(name = "REQUEST_JSON", length = 16000, nullable = false, updatable = false) String request;
  @Column(name = "APPROVAL_REQUEST_DIGEST", length = 64, nullable = false, updatable = false) String requestDigest;
  @Column(name = "SCOPE_JSON", length = 24000, nullable = false, updatable = false) String scope;
  @Column(name = "SCOPE_DIGEST", length = 64, nullable = false, updatable = false) String scopeDigest;
  @Column(name = "ISSUER_SUBJECT", length = 36, nullable = false, updatable = false) String issuerSubject;
  @Column(name = "APPROVAL_RECEIPT", length = 24000, updatable = false) String approvalReceipt;
  @Column(name = "VALID_UNTIL", length = 30, nullable = false, updatable = false) String validUntil;
  @Column(name = "STATE", length = 30, nullable = false) String state;
  @Column(name = "BOUND_ATTEMPT_ID", length = 36) String boundAttemptId;
  // Set only by the atomic first protected COMMIT/CONSUME; never by approval/create.
  @Column(name = "DELEGATED_SUBJECT", length = 36) String delegatedSubject;
  @Column(name = "DELEGATION_SNAPSHOT", length = 16000) String delegationSnapshot;
  @Version @Column(name = "VERSION", nullable = false) long version;
  protected ProtectedInvitationApproval() {}
}
