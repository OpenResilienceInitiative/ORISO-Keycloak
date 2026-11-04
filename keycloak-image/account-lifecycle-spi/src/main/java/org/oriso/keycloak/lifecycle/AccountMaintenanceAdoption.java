package org.oriso.keycloak.lifecycle;

import jakarta.persistence.*;

/** Receiver-owned immutable incarnation anchor for one explicitly reviewed adopted profile. */
@Entity @Table(name="ORISO_ACCOUNT_MAINTENANCE_ADOPTION")
public class AccountMaintenanceAdoption {
  @Id @Column(name="ID",length=64) String id;
  @Column(name="REALM_ID",nullable=false,updatable=false) String realmId;
  @Column(name="ACCOUNT_ID",nullable=false,updatable=false) String accountId;
  @Column(name="PROFILE_KIND",length=20,nullable=false,updatable=false) String kind;
  @Column(name="SNAPSHOT_JSON",length=16000,nullable=false,updatable=false) String snapshotJson;
  @Column(name="BINDING_MAC",length=64,nullable=false,updatable=false) String bindingMac;
  protected AccountMaintenanceAdoption(){}
}
