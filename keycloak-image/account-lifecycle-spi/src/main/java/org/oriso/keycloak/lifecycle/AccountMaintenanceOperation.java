package org.oriso.keycloak.lifecycle;

import jakarta.persistence.*;

/** Immutable native outcome. No credential, raw payload, token or human session is persisted. */
@Entity
@Table(name = "ORISO_ACCOUNT_MAINTENANCE_OP")
public class AccountMaintenanceOperation {
  @Id
  @Column(name = "ID", length = 255)
  String id;

  @Column(name = "REALM_ID", length = 255, nullable = false, updatable = false)
  String realmId;
  @Column(name = "OPERATION_ID", length = 36, nullable = false, updatable = false)
  String operationId;
  @Column(name = "ACCOUNT_ID", length = 255, nullable = false, updatable = false)
  String accountId;
  @Column(name = "COMMAND", length = 40, nullable = false, updatable = false)
  String command;
  @Column(name = "OWNER_CLIENT", length = 255, nullable = false, updatable = false)
  String ownerClient;
  @Column(name = "OWNER_SUBJECT", length = 255, nullable = false, updatable = false)
  String ownerSubject;
  @Column(name = "INTENT_DIGEST", length = 64, nullable = false, updatable = false)
  String intentDigest;
  @Column(name = "EXPECTED_STATE", length = 64, nullable = false, updatable = false)
  String expectedState;
  @Column(name = "RESULT_JSON", length = 16000, nullable = false, updatable = false)
  String resultJson;

  protected AccountMaintenanceOperation() {}
}
