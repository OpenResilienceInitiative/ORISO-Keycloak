package org.oriso.keycloak.lifecycle;

import jakarta.persistence.*;

/** Immutable workflow ownership; a missing native session never permits replacement/adoption. */
@Entity
@Table(name="ORISO_MAGIC_LINK_SESSION")
public class MagicLinkSession {
  @Id @Column(name="ID",length=255) String id;
  @Column(name="REALM_ID",nullable=false,updatable=false,length=255) String realmId;
  @Column(name="WORKFLOW_ID",nullable=false,updatable=false,length=36) String workflow;
  @Column(name="TARGET_ID",nullable=false,updatable=false,length=255) String target;
  @Column(name="CLIENT_ID",nullable=false,updatable=false,length=255) String client;
  @Column(name="OWNER_CLIENT",nullable=false,updatable=false,length=255) String ownerClient;
  @Column(name="OWNER_SUBJECT",nullable=false,updatable=false,length=255) String ownerSubject;
  @Column(name="COMMAND_DIGEST",nullable=false,updatable=false,length=64) String digest;
  @Column(name="NATIVE_SESSION_ID",nullable=false,updatable=false,unique=true,length=255) String sessionId;
  @Column(name="EXPIRES_AT",nullable=false,updatable=false) long expiry;
  protected MagicLinkSession() {}
}
