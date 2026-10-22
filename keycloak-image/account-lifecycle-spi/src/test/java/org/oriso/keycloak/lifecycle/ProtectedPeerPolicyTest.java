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
  }

  @Test
  public void anExplicitEmptyPolicySetRemainsNonDelegating() throws Exception {
    var value = base(); value.putArray("peerDelegationPolicies"); assertAccepted(value);
  }

  @Test
  public void oneReviewedSourceProfileCanDeclareItsFiniteOwnTenantPeerPolicy() throws Exception {
    assertAccepted(configured());
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
