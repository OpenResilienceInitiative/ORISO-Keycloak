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
  }

  @Test
  public void exactReviewedSelfPolicyCanNameClosedOtpOperations() {
    accepted("account.read", "account.locale", "account.profile", "account.password", "otp.read", "otp.app-setup",
        "otp.delete", "otp.email-start", "otp.email-finish");
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

  private static void rejected(String operation) {
    try {
      new GeneralPolicy(policy(operation));
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
