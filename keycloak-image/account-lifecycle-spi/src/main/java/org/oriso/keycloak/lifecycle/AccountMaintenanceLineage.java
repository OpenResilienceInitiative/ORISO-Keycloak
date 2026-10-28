package org.oriso.keycloak.lifecycle;

import jakarta.persistence.*;

/** Immutable approved profile/tenant transition; native effect and outcome commit together. */
@Entity
@Table(name = "ORISO_ACCOUNT_MAINTENANCE_LINEAGE", uniqueConstraints =
    @UniqueConstraint(columnNames = {"REALM_ID", "ACCOUNT_ID", "SEQUENCE_NO"}))
public class AccountMaintenanceLineage {
  @Id @Column(name = "ID", length = 255) String id;
  @Column(name = "REALM_ID", length = 255, nullable = false, updatable = false) String realmId;
  @Column(name = "ACCOUNT_ID", length = 255, nullable = false, updatable = false) String accountId;
  @Column(name = "SEQUENCE_NO", nullable = false, updatable = false) long sequence;
  @Column(name = "OPERATION_ID", length = 36, nullable = false, updatable = false) String operationId;
  @Column(name = "SNAPSHOT_JSON", length = 16000, nullable = false, updatable = false) String snapshotJson;
  @Column(name = "LINEAGE_DIGEST", length = 64, nullable = false, updatable = false) String lineageDigest;
  protected AccountMaintenanceLineage() {}
}
