package org.oriso.keycloak.lifecycle;

import jakarta.persistence.*;

/** One original claim reserves one full intent. Contains no password, recipient or raw token. */
@Entity
@Table(name="ORISO_CAUSAL_PASSWORD_CLAIM")
public class CausalPasswordClaim {
  @Id @Column(name="ID",length=64) String id;
  @Column(name="REALM_ID",nullable=false,updatable=false) String realmId;
  @Column(name="ACCOUNT_ID",nullable=false,updatable=false) String accountId;
  @Column(name="CLAIM_KIND",length=20,nullable=false,updatable=false) String kind;
  @Column(name="CLAIM_ID",length=36,nullable=false,updatable=false) String claimId;
  @Column(name="CLAIM_VERSION",nullable=false,updatable=false) long claimVersion;
  @Column(name="OWNER_CLIENT",nullable=false,updatable=false) String ownerClient;
  @Column(name="OWNER_SUBJECT",nullable=false,updatable=false) String ownerSubject;
  @Column(name="TARGET_DIGEST",length=64,nullable=false,updatable=false) String targetDigest;
  @Column(name="WORKFLOW_DIGEST",length=64,nullable=false,updatable=false) String workflowDigest;
  @Column(name="OPERATION_ID",length=36,nullable=false,updatable=false) String operationId;
  @Column(name="INTENT_DIGEST",length=64,nullable=false,updatable=false) String intentDigest;
  @Column(name="EXPECTED_STATE",length=64,nullable=false,updatable=false) String expectedState;
  @Column(name="BINDING_MAC",length=64,nullable=false,updatable=false) String bindingMac;
  protected CausalPasswordClaim() {}
}
