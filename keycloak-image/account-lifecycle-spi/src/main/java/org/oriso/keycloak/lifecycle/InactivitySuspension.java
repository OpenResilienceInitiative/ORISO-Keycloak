package org.oriso.keycloak.lifecycle;

import jakarta.persistence.*;

/** Actual original enabled flag commits with the acknowledged native suspend operation. */
@Entity @Table(name="ORISO_INACTIVITY_SUSPENSION")
public class InactivitySuspension {
  @Id @Column(name="ID",length=255) String id;
  @Column(name="REALM_ID",nullable=false,updatable=false) String realmId;
  @Column(name="ACCOUNT_ID",nullable=false,updatable=false) String accountId;
  @Column(name="OPERATION_ID",length=36,nullable=false,updatable=false) String operationId;
  @Column(name="BINDING_JSON",length=16000,nullable=false,updatable=false) String bindingJson;
  @Column(name="BINDING_MAC",length=64,nullable=false,updatable=false) String bindingMac;
  protected InactivitySuspension(){}
}
