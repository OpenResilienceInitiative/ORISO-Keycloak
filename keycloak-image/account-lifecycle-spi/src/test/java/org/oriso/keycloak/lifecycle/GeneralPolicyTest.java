package org.oriso.keycloak.lifecycle;

import static org.junit.Assert.*;
import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import jakarta.ws.rs.WebApplicationException;
import org.junit.Test;

/** Closed installation selectors do not grant a runtime OTP capability. */
public class GeneralPolicyTest {
  @Test
  public void existingReviewedSelfOperationsStillParse() {
    accepted("account.read", "account.locale", "account.profile", "account.password");
    accepted("account.read", "account.locale", "account.profile", "account.password", "account.email", "otp.read", "otp.app-setup",
        "otp.delete", "otp.email-start", "otp.email-finish");
    String[] complete = {"account.read", "account.locale", "account.profile", "account.email", "account.password",
        "account.deactivate", "otp.read", "otp.app-setup", "otp.delete", "otp.email-start", "otp.email-finish"};
    accepted(complete);
    String[] duplicate = complete.clone();
    duplicate[10] = "account.read";
    rejected(duplicate);
    String[] unknown = complete.clone();
    unknown[10] = "account.unreviewed";
    rejected(unknown);
    String[] extra = java.util.Arrays.copyOf(complete, 12);
    extra[11] = "account.read";
    rejected(extra);
    rejected("account.email", "account.email");
    rejected("account.email", "account.profile-transition");
    rejected("account.email", "account.ordinary-profile");
    rejected("account.email", "account.self-password");
  }

  @Test
  public void exactReviewedSelfPolicyCanNameClosedOtpOperations() {
    accepted("account.read", "account.locale", "account.profile", "account.password", "otp.read", "otp.app-setup",
        "otp.delete", "otp.email-start", "otp.email-finish");
  }

  @Test
  public void explicitOrdinaryAdministrationNeedsClosedReviewedProfilesAndOperations() {
    var value = (com.fasterxml.jackson.databind.node.ObjectNode) policy("account.read");
    var grant = value.putArray("adminOperations").addObject();
    grant.put("authority", "TENANT_PEER");
    grant.putArray("targetProfiles").add("reviewed-consultant-v1");
    grant.putArray("operations").add("account.read").add("account.profile").add("account.email")
        .add("account.ordinary-profile").add("account.deactivate").add("account.reactivate").add("account.profile-transition");
    grant.put("selfOnly", false);
    try { assertNotNull(new GeneralPolicy(value)); }
    catch (WebApplicationException rejected) {
      fail("Exact independently reviewed ordinary administration rejected with status "
          + rejected.getResponse().getStatus());
    }
    var platform = value.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode)platform.path("adminOperations").path(0)).put("authority", "PLATFORM");
    assertNotNull(new GeneralPolicy(platform));
    for (String field : java.util.List.of("authority", "targetProfiles", "operations", "selfOnly")) {
      var missing = value.deepCopy();
      ((com.fasterxml.jackson.databind.node.ObjectNode)missing.path("adminOperations").path(0)).remove(field);
      rejectAdmin(missing);
    }
    for (String op : java.util.List.of("*", "account.*", "otp.read", "account.password", "protected.approve")) {
      var foreign = value.deepCopy();
      ((com.fasterxml.jackson.databind.node.ObjectNode)foreign.path("adminOperations").path(0)).putArray("operations").add(op);
      rejectAdmin(foreign);
    }
    var foreignProfile = value.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode)foreignProfile.path("adminOperations").path(0)).putArray("targetProfiles").add("protected-platform-v1");
    rejectAdmin(foreignProfile);
    var self = value.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode)self.path("adminOperations").path(0)).put("selfOnly", true);
    rejectAdmin(self);
    var duplicate = value.deepCopy();
    ((com.fasterxml.jackson.databind.node.ArrayNode)duplicate.path("adminOperations")).add(grant.deepCopy());
    rejectAdmin(duplicate);
    var absent = (com.fasterxml.jackson.databind.node.ObjectNode) policy("account.read");
    assertNotNull(new GeneralPolicy(absent));
    absent.putArray("adminOperations");
    assertNotNull(new GeneralPolicy(absent));
  }

  @Test
  public void ordinaryOperatorsAreDefaultEmptyAndKeepExactProfileVerbPairs(){
    var value=(com.fasterxml.jackson.databind.node.ObjectNode)policy("account.read");
    var source=((com.fasterxml.jackson.databind.node.ObjectNode)value.path("ordinaryProfiles").path(0)).deepCopy();
    source.put("id","agency-v1");source.put("groupId","agency-group");source.put("groupPath","/human-roles/agency-admin");
    source.putArray("realmRoles").add("restricted-agency-admin").add("user-admin");
    ((com.fasterxml.jackson.databind.node.ArrayNode)value.path("ordinaryProfiles")).add(source);
    value.putArray("ordinaryAdminOperations");assertNotNull(new GeneralPolicy(value));
    var grant=value.putArray("ordinaryAdminOperations").addObject();grant.putArray("sourceProfiles").add("agency-v1");
    grant.putArray("targetProfiles").add("reviewed-consultant-v1");grant.putArray("operations").add("account.read").add("account.deactivate");
    assertNotNull(new GeneralPolicy(value));
    for(String op:List.of("account.delete","account.email","account.reactivate","otp.delete","account.profile-transition","*")){
      var wrong=value.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)wrong.path("ordinaryAdminOperations").path(0)).putArray("operations").add(op);rejectAdmin(wrong);
    }
    for(String field:List.of("sourceProfiles","targetProfiles")){
      var wrong=value.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)wrong.path("ordinaryAdminOperations").path(0)).putArray(field).add(field.equals("sourceProfiles")?"reviewed-consultant-v1":"agency-v1");rejectAdmin(wrong);
    }
    var editable=value.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode)editable.path("ordinaryAdminOperations").path(0)).putArray("operations")
        .add("account.read").add("account.profile").add("account.ordinary-profile");
    try { assertNotNull(new GeneralPolicy(editable)); }
    catch (WebApplicationException refused) { fail("Reviewed ordinary consultant edits refused with status " + refused.getResponse().getStatus()); }
    var asker=source.deepCopy();asker.put("id","asker-v1");asker.put("groupId","asker-group");asker.put("groupPath","/human-roles/user");asker.putArray("realmRoles").add("user");
    ((com.fasterxml.jackson.databind.node.ArrayNode)editable.path("ordinaryProfiles")).add(asker);
    ((com.fasterxml.jackson.databind.node.ObjectNode)editable.path("ordinaryAdminOperations").path(0)).putArray("targetProfiles").add("asker-v1");
    rejectAdmin(editable);
    var combined=source.deepCopy();combined.put("id","combined-v1");combined.put("groupId","combined-group");combined.put("groupPath","/human-roles/consultant-agency-admin");
    combined.putArray("realmRoles").add("consultant").add("group-chat-consultant").add("restricted-agency-admin").add("user-admin");
    ((com.fasterxml.jackson.databind.node.ArrayNode)value.path("ordinaryProfiles")).add(combined);
    var own=(com.fasterxml.jackson.databind.node.ObjectNode)value.path("ordinaryAdminOperations").path(0);
    own.putArray("sourceProfiles").add("agency-v1").add("combined-v1");own.putArray("targetProfiles").add("agency-v1").add("combined-v1");
    own.putArray("operations").add("account.read").add("account.profile-transition");
    try { assertNotNull(new GeneralPolicy(value)); }
    catch (WebApplicationException refused) { fail("Reviewed ordinary own Consultant grant refused with status " + refused.getResponse().getStatus()); }
    var extra=value.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)extra.path("ordinaryAdminOperations").path(0)).put("authority","PLATFORM");rejectAdmin(extra);
    var duplicate=value.deepCopy();((com.fasterxml.jackson.databind.node.ArrayNode)duplicate.path("ordinaryAdminOperations")).add(grant.deepCopy());rejectAdmin(duplicate);
  }

  @Test
  public void inactivityWorkflowGrantsAreExplicitClosedAndDefaultEmpty() {
    var value = (com.fasterxml.jackson.databind.node.ObjectNode) policy("account.read");
    var grant = value.putArray("workflowOperations").addObject();
    grant.put("kind", "INACTIVITY"); grant.putArray("targetProfiles").add("reviewed-consultant-v1");
    grant.putArray("operations").add("account.reactivate").add("account.read").add("account.deactivate");
    try { assertNotNull(new GeneralPolicy(value)); }
    catch (WebApplicationException refused) { fail("Reviewed workflow grant rejected with status " + refused.getResponse().getStatus()); }
    for (String extra : List.of("authority", "selfOnly", "subject")) {
      var wrong = value.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) wrong.path("workflowOperations").path(0)).put(extra, "unreviewed"); rejectAdmin(wrong);
    }
    for (String op : List.of("*", "account.profile", "account.delete", "otp.read")) {
      var wrong = value.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) wrong.path("workflowOperations").path(0)).putArray("operations").add(op); rejectAdmin(wrong);
    }
    var unknown = value.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) unknown.path("workflowOperations").path(0)).putArray("targetProfiles").add("protected-platform-v1"); rejectAdmin(unknown);
    var duplicate = value.deepCopy(); ((com.fasterxml.jackson.databind.node.ArrayNode) duplicate.path("workflowOperations")).add(grant.deepCopy()); rejectAdmin(duplicate);
    var empty = (com.fasterxml.jackson.databind.node.ObjectNode) policy("account.read"); empty.putArray("workflowOperations"); assertNotNull(new GeneralPolicy(empty));
    assertThrows(jakarta.ws.rs.ForbiddenException.class,()->new GeneralPolicy(empty).workflowOperations.require("reviewed-consultant-v1","account.read"));
    var imported=value.deepCopy();var importGrant=(com.fasterxml.jackson.databind.node.ObjectNode)imported.path("workflowOperations").path(0);
    importGrant.put("kind","IMPORT");importGrant.putArray("operations").add("account.read").add("account.ordinary-profile");
    try{assertNotNull(new GeneralPolicy(imported));}catch(WebApplicationException refused){fail("Reviewed import grant rejected with status "+refused.getResponse().getStatus());}
    importGrant.putArray("operations").add("account.reactivate");rejectAdmin(imported);

  }

  @Test
  public void ordinaryAdoptionHasOnlyExactInstalledProfileAndVersion() {
    var value=(com.fasterxml.jackson.databind.node.ObjectNode) policy("account.read");
    var profile=((com.fasterxml.jackson.databind.node.ObjectNode)value.path("ordinaryProfiles").path(0)).deepCopy();
    profile.put("id","reviewed-user-v2");profile.put("version",2);profile.put("groupId","user-group");profile.put("groupPath","/human-roles/user");profile.putArray("realmRoles").add("user");
    ((com.fasterxml.jackson.databind.node.ArrayNode)value.path("ordinaryProfiles")).add(profile);
    var entry=value.putArray("adoptedAccounts").addObject();entry.put("accountId","aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");entry.put("ordinaryProfileId","reviewed-user-v2");entry.put("profileVersion",2);
    try { assertNotNull(new GeneralPolicy(value)); } catch(WebApplicationException refused){fail("Reviewed ordinary adoption rejected with status "+refused.getResponse().getStatus());}
    for(String field:List.of("accountId","ordinaryProfileId","profileVersion")){var wrong=value.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)wrong.path("adoptedAccounts").path(0)).remove(field);rejectAdmin(wrong);}
    var stale=value.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)stale.path("adoptedAccounts").path(0)).put("profileVersion",1);rejectAdmin(stale);
    var unknown=value.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)unknown.path("adoptedAccounts").path(0)).put("ordinaryProfileId","missing");rejectAdmin(unknown);
    var duplicate=value.deepCopy();((com.fasterxml.jackson.databind.node.ArrayNode)duplicate.path("adoptedAccounts")).add(entry.deepCopy());rejectAdmin(duplicate);
    var extra=value.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)extra.path("adoptedAccounts").path(0)).put("authority","DELETE");rejectAdmin(extra);
  }

  private static void rejectAdmin(JsonNode value) {
    try { new GeneralPolicy(value); fail("Unreviewed ordinary admin policy accepted"); }
    catch (WebApplicationException rejected) { assertEquals(400, rejected.getResponse().getStatus()); }
  }

  @Test
  public void unknownAndWildcardSelectorsAreRejected() {
    rejected("unknown");
    rejected("*");
    rejected("otp.*");
  }

  @Test
  public void foreignOperationSelectorsAreRejected() {
    rejected("otp.native-proxy");
    rejected("account.delete");
    rejected("protected.approve");
  }

  private static void accepted(String... operations) {
    try {
      assertNotNull(new GeneralPolicy(policy(operations)));
    } catch (WebApplicationException rejected) {
      fail("Exact reviewed ordinary SELF selector rejected with status "
          + rejected.getResponse().getStatus());
    }
  }

  private static void rejected(String... operations) {
    try {
      new GeneralPolicy(policy(operations));
      fail("Unreviewed operation selector accepted");
    } catch (WebApplicationException rejected) {
      assertEquals(400, rejected.getResponse().getStatus());
    }
  }

  private static JsonNode policy(String... operations) {
    var policy = JSON.createObjectNode();
    policy.put("version", 1);
    var nativePolicy = policy.putObject("native");
    nativePolicy.put("realmId", "reviewed-realm");
    nativePolicy.put("issuer", "https://auth.test/realms/reviewed");
    nativePolicy.putArray("clientIds").add("app");
    nativePolicy.putArray("audienceSets").addArray().add("app");
    var subjects = nativePolicy.putArray("technicalSubjects");
    for (int index = 1; index <= 5; index++)
      subjects.add("00000000-0000-4000-8000-00000000000" + index);
    nativePolicy.putArray("technicalGroupIds").add("technical-group");
    var technicalRoles = nativePolicy.putArray("technicalRoles");
    List.of("config-wizard", "invitation-reservations", "consultant-import",
        "account-provisioning", "account-read", "account-maintenance", "otp-config-admin",
        "session-exchange", "smtp-sync", "system-email-delivery", "notification-dispatch",
        "notifications-technical", "runtime-policy", "matrix-agency", "matrix-agency-provision",
        "appointment-sync", "appointment-participant-cleanup").stream().sorted()
        .forEach(technicalRoles::add);
    var profile = policy.putArray("ordinaryProfiles").addObject();
    profile.put("id", "reviewed-consultant-v1");
    profile.put("version", 1);
    profile.put("groupId", "consultant-group");
    profile.put("groupPath", "/human-roles/consultant");
    profile.put("groupParentId", "human-roles-group");
    profile.putArray("realmRoles").add("consultant").add("group-chat-consultant");
    profile.putObject("clientRoles");
    profile.put("allowUnassignedTenant", false);
    var selected = profile.putArray("selfOperations");
    for (String operation : operations) selected.add(operation);
    return policy;
  }
}
