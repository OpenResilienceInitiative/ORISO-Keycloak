package org.oriso.keycloak.lifecycle;

import static org.junit.Assert.*;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.ws.rs.BadRequestException;
import org.junit.Test;

/** Installation metadata only; these tests do not grant a native human any authority. */
public class ProtectedPeerPolicyTest {
  @Test
  public void existingExplicitPrimaryInstallationRemainsAcceptedWithoutPeerPolicies() throws Exception {
    assertAccepted(base());
    var operations = base();
    ((ObjectNode)operations.path("bindings").get(0)).putArray("accountOperations")
        .add(operationGrant("PLATFORM", "platform-v1"));
    operations.putArray("adoptedAccounts").addObject()
        .put("accountId", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        .put("protectedProfileId", "platform-v1").put("profileVersion", 1);
    assertAccepted(operations);
    var transition = operationGrant("PLATFORM", "platform-v1"); transition.put("selfOnly", false);
    transition.putArray("operations").add("account.profile-transition");
    ((ObjectNode)operations.path("bindings").get(0)).putArray("accountOperations").add(transition);
    assertAccepted(operations);
    var parsed = new ProtectedInvitationConfiguration(operations);
    assertEquals(1, parsed.bindingAccountOperations.values().iterator().next().size());
    assertEquals("platform-v1", parsed.adoptedAccounts.get("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").profileId());
    assertTrue(new ProtectedInvitationConfiguration(base()).adoptedAccounts.isEmpty());
    assertTrue(new ProtectedInvitationConfiguration(base()).bindingAccountOperations.values().stream().allMatch(java.util.List::isEmpty));
  }

  @Test
  public void anExplicitEmptyPolicySetRemainsNonDelegating() throws Exception {
    var value = base(); value.putArray("peerDelegationPolicies"); assertAccepted(value);
    value.putArray("adoptedAccounts");
    ((ObjectNode)value.path("bindings").get(0)).putArray("accountOperations"); assertAccepted(value);
  }

  @Test
  public void oneReviewedSourceProfileCanDeclareItsFiniteOwnTenantPeerPolicy() throws Exception {
    assertAccepted(configured());
    var operations = configured();
    policy(operations).putArray("accountOperations").add(operationGrant("TENANT_PEER", "tenant-v1"));
    assertAccepted(operations);
    assertEquals(1, new ProtectedInvitationConfiguration(operations).peerAccountOperations.get("own-tenant-admin-v1").size());
    assertEquals(LifecycleJson.canonical(new ProtectedInvitationConfiguration(configured()).peerPolicies.get("own-tenant-admin-v1").snapshot()),
        LifecycleJson.canonical(new ProtectedInvitationConfiguration(operations).peerPolicies.get("own-tenant-admin-v1").snapshot()));
  }

  @Test
  public void unknownPolicyFieldsCannotNameNewHumanBindingsOrBroaderAuthority() throws Exception {
    for (String field : new String[] {"subject", "authorizerTenantIds", "tenantModes", "authority", "extra"}) {
      var value = configured(); policy(value).put(field, "unreviewed"); assertRejected(value);
    }
  }

  @Test
  public void duplicateIdsOrAmbiguousSourceProfileRulesAreRefused() throws Exception {
    var duplicate = configured(); policies(duplicate).add(policy(duplicate).deepCopy()); assertRejected(duplicate);
    var ambiguous = configured(); var other = policy(ambiguous).deepCopy(); other.put("id", "other-rule"); policies(ambiguous).add(other); assertRejected(ambiguous);
  }

  @Test
  public void sourceProfileMustExistHaveTheExactVersionAndBeTenantAdministrator() throws Exception {
    var unknown = configured(); policy(unknown).put("sourceProfileId", "missing-profile"); assertRejected(unknown);
    var stale = configured(); policy(stale).put("sourceProfileVersion", 2); assertRejected(stale);
    var platform = configured(); policy(platform).put("sourceProfileId", "platform-v1"); assertRejected(platform);
  }

  @Test
  public void targetsMustBeReviewedTenantProfilesThatPermitExistingTenants() throws Exception {
    for (String target : new String[] {"missing-profile", "platform-v1"}) {
      var value = configured(); policy(value).putArray("protectedProfileIds").add(target); assertRejected(value);
    }
    var newOnly = configured(); ((ObjectNode)newOnly.path("profiles").get(1)).putArray("tenantModes").add("RESERVED_NEW"); assertRejected(newOnly);
  }

  @Test
  public void policyFullGrantsMustEqualTheCompleteReviewedSourceProfile() throws Exception {
    var extra = configured(); policy(extra).putArray("realmRoles").add("tenant-admin").add("user-admin"); assertRejected(extra);
    var client = configured(); policy(client).putObject("clientRoles").putArray("admin-panel").add("editor"); assertRejected(client);
    var removed = configured(); policy(removed).putArray("realmRoles"); assertRejected(removed);
  }

  @Test
  public void serviceClientsTechnicalGrantsAndRealmManagementNeverBecomePeerPolicy() throws Exception {
    var machine = configured(); policy(machine).putArray("humanClientIds").add("backend-setup"); assertRejected(machine);
    var technical = configured(); policy(technical).putArray("realmRoles").add("config-wizard"); assertRejected(technical);
    var admin = configured(); policy(admin).putObject("clientRoles").putArray("realm-management").add("manage-users"); assertRejected(admin);
  }

  @Test
  public void arraySizeTypesPolicyVersionAndAudienceSetsAreBounded() throws Exception {
    var big = configured(); var original = policy(big).deepCopy(); for(int i=1;i<101;i++){var next=original.deepCopy();next.put("id","rule-"+i);policies(big).add(next);} assertRejected(big);
    var wrongType = configured(); wrongType.put("peerDelegationPolicies", "[]"); assertRejected(wrongType);
    for(long version : new long[]{0,-1}){var value=configured();policy(value).put("version",version);assertRejected(value);}
    var duplicateAudience = configured(); var sets=(ArrayNode)policy(duplicateAudience).path("audienceSets"); sets.add(sets.get(0).deepCopy()); assertRejected(duplicateAudience);
    for(String operation : new String[]{"*", "otp.*", "account.create", "grant-role", "foreign.read"}) {
      var value=configured(); var grant=operationGrant("TENANT_PEER", "tenant-v1");
      grant.putArray("operations").add(operation); policy(value).putArray("accountOperations").add(grant); assertRejected(value);
    }
    for(String target : new String[]{"missing", "platform-v1"}) {
      var value=configured(); policy(value).putArray("accountOperations").add(operationGrant("TENANT_PEER", target)); assertRejected(value);
    }
    var platformPeer=configured(); policy(platformPeer).putArray("accountOperations").add(operationGrant("PLATFORM", "tenant-v1")); assertRejected(platformPeer);
    var unknown=configured(); var extra=operationGrant("TENANT_PEER", "tenant-v1"); extra.put("authorityFromApproval", true); policy(unknown).putArray("accountOperations").add(extra); assertRejected(unknown);
    for(String profile : new String[]{"missing", "tenant-v1"}) {
      var adoption=configured(); adoption.putArray("adoptedAccounts").addObject()
          .put("accountId","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
          .put("protectedProfileId",profile).put("profileVersion",2); assertRejected(adoption);
    }
    var duplicate=configured(); var grant=operationGrant("TENANT_PEER","tenant-v1");
    policy(duplicate).putArray("accountOperations").add(grant).add(grant.deepCopy()); assertRejected(duplicate);
    var wrongBoolean=configured(); grant=operationGrant("TENANT_PEER","tenant-v1"); grant.put("selfOnly","true");
    policy(wrongBoolean).putArray("accountOperations").add(grant); assertRejected(wrongBoolean);
    var duplicateOperation=configured(); grant=operationGrant("TENANT_PEER","tenant-v1");
    grant.putArray("operations").add("otp.read").add("otp.read");
    policy(duplicateOperation).putArray("accountOperations").add(grant); assertRejected(duplicateOperation);
    var wrongSubject=configured(); grant=operationGrant("TENANT_PEER","tenant-v1");
    grant.putArray("targetSubjects").add("not-a-native-uuid");
    policy(wrongSubject).putArray("accountOperations").add(grant); assertRejected(wrongSubject);
    var duplicateAccount=base(); var adopted=duplicateAccount.putArray("adoptedAccounts");
    adopted.addObject().put("accountId","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        .put("protectedProfileId","platform-v1").put("profileVersion",1);
    adopted.add(adopted.get(0).deepCopy()); assertRejected(duplicateAccount);
  }

  @Test
  public void protectedInactivityWorkflowGrantsAreSeparateFromHumanOperations() throws Exception {
    var value = base(); var grant = value.putArray("workflowOperations").addObject();
    grant.put("kind", "INACTIVITY"); grant.putArray("targetProfiles").add("platform-v1").add("tenant-v1");
    grant.putArray("operations").add("account.reactivate").add("account.read").add("account.deactivate");
    assertAccepted(value);
    for (String extra : new String[]{"authority", "selfOnly", "subject"}) {
      var wrong=value.deepCopy(); ((ObjectNode)wrong.path("workflowOperations").path(0)).put(extra,"unreviewed"); assertRejected(wrong);
    }
    for (String op : new String[]{"*", "account.profile", "account.delete", "otp.read"}) {
      var wrong=value.deepCopy(); ((ObjectNode)wrong.path("workflowOperations").path(0)).putArray("operations").add(op); assertRejected(wrong);
    }
    var unknown=value.deepCopy(); ((ObjectNode)unknown.path("workflowOperations").path(0)).putArray("targetProfiles").add("missing"); assertRejected(unknown);
    var duplicate=value.deepCopy(); ((ArrayNode)duplicate.path("workflowOperations")).add(grant.deepCopy()); assertRejected(duplicate);
    var empty=base(); empty.putArray("workflowOperations"); assertAccepted(empty);
    var imported=value.deepCopy();var importGrant=(ObjectNode)imported.path("workflowOperations").path(0);
    importGrant.put("kind","IMPORT");importGrant.putArray("operations").add("account.read");assertAccepted(imported);
    importGrant.putArray("operations").add("account.ordinary-profile");assertRejected(imported);

  }

  @Test
  public void tenantReassignmentGrantIsPlatformOnlyForTenantProfile() throws Exception {
    var value=base(); var grant=operationGrant("PLATFORM","tenant-v1");
    grant.put("selfOnly",false); grant.putArray("operations").add("account.reassign-tenant");
    ((ObjectNode)value.path("bindings").path(0)).putArray("accountOperations").add(grant); assertAccepted(value);
    var self=value.deepCopy(); ((ObjectNode)self.path("bindings").path(0).path("accountOperations").path(0)).put("selfOnly",true); assertRejected(self);
    var platform=value.deepCopy(); ((ObjectNode)platform.path("bindings").path(0).path("accountOperations").path(0)).putArray("targetProfiles").add("platform-v1"); assertRejected(platform);
    var peer=configured(); grant=operationGrant("TENANT_PEER","tenant-v1"); grant.put("selfOnly",false); grant.putArray("operations").add("account.reassign-tenant"); policy(peer).putArray("accountOperations").add(grant); assertRejected(peer);
  }

  private ObjectNode base() throws Exception {
    try(var input=getClass().getResourceAsStream("/protected-peer-policy-installation.json")) {
      assertNotNull(input); return (ObjectNode)LifecycleJson.JSON.readTree(input);
    }
  }

  private ObjectNode configured() throws Exception {
    var value=base(); policies(value).add(LifecycleJson.parse("""
        {"id":"own-tenant-admin-v1","version":1,"sourceProfileId":"tenant-v1","sourceProfileVersion":1,
         "humanClientIds":["protected-human-web"],"audienceSets":[["userservice"]],
         "protectedProfileIds":["tenant-v1"],"realmRoles":["tenant-admin"],"clientRoles":{}}
        """)); return value;
  }
  private ObjectNode operationGrant(String authority, String target) {
    var grant=LifecycleJson.JSON.createObjectNode();grant.put("authority",authority);
    grant.putArray("targetProfiles").add(target); grant.put("selfOnly",true);grant.putArray("targetSubjects");
    grant.putArray("operations").add("otp.app-setup").add("otp.delete").add("otp.email-finish").add("otp.email-start").add("otp.read");
    return grant;
  }
  private ArrayNode policies(ObjectNode value) {
    if(!value.has("peerDelegationPolicies"))return value.putArray("peerDelegationPolicies");
    return (ArrayNode)value.path("peerDelegationPolicies");
  }
  private ObjectNode policy(ObjectNode value) { return (ObjectNode)policies(value).get(0); }
  private void assertAccepted(ObjectNode value) {
    boolean accepted;
    try {new ProtectedInvitationConfiguration(value);accepted=true;}
    catch(BadRequestException denied){accepted=false;}
    assertTrue("Reviewed finite installation metadata must be accepted",accepted);
  }
  private void assertRejected(ObjectNode value) {
    assertThrows(BadRequestException.class, () -> new ProtectedInvitationConfiguration(value));
  }
}
