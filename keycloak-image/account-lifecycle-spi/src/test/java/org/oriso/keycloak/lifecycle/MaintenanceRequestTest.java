package org.oriso.keycloak.lifecycle;

import static org.junit.Assert.*;
import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import jakarta.ws.rs.WebApplicationException;
import org.junit.Test;

/** Public receiver parser: schema rejects unbounded fields before touching a native user. */
public class MaintenanceRequestTest {
  private static final String ID = "194b23de-93d9-4d1e-990f-4bf4c96b9dd8";
  private static final String OPERATION = "8c038518-f5e2-4557-9fa9-2698286b998c";
  private static final String TARGET =
      "\"target\":{\"accountId\":\"" + ID + "\",\"tenantId\":\"1\","
          + "\"origin\":{\"kind\":\"SELF\",\"workflowId\":\"self-session-1\","
          + "\"humanSubject\":\"" + ID + "\",\"humanIssuer\":\"https://auth.test/realms/r\","
          + "\"humanClient\":\"app\",\"humanAuthority\":null}}";

  @Test
  public void parsesOnlyTheSpecificLocaleFields() {
    var request = accepted("locale", "{\"locale\":\"de\"}");
    assertEquals(ID, request.accountId());
    assertEquals("de", request.change().path("locale").asText());
  }

  @Test
  public void nativeRepresentationFieldsCannotRideInsideProfile() {
    rejected("profile", "{\"firstName\":\"a\",\"lastName\":\"b\",\"email\":null,"
        + "\"enabled\":true,\"attributes\":{\"tenantId\":[\"0\"]}}");
  }

  @Test
  public void pathAndTargetMustMatch() {
    try {
      MaintenanceRequest.parse("locale", "foreign", parse(command("{\"locale\":\"de\"}")));
      fail("Foreign target accepted");
    } catch (WebApplicationException expected) {
      assertEquals(403, expected.getResponse().getStatus());
    }
  }

  @Test
  public void passwordIsNeverRenderedByTheTypedRequest() {
    var request = accepted("password", "{\"password\":\"secret-do-not-log\",\"temporary\":false}");
    assertFalse(request.toString().contains("secret-do-not-log"));
  }

  @Test
  public void cannotSupplyAnArbitraryRoleOrRoleList() {
    rejected("ordinary-profile", "{\"group\":\"/human-roles/consultant\",\"roles\":[\"realm-admin\"]}");
  }

  @Test
  public void requiredStateAndOperationIdentityCannotBeOmitted() {
    try {
      MaintenanceRequest.parse("deactivate", ID, parse("{" + TARGET + ",\"change\":{}}"));
      fail("Missing mutation identity accepted");
    } catch (WebApplicationException expected) {
      assertEquals(400, expected.getResponse().getStatus());
    }
  }

  @Test
  public void onlyKnownMaintenanceCommandsAreAccepted() {
    rejected("create", "{}");
    rejected("native-proxy", "{}");
  }

  @Test
  public void exactAvailabilityRejectsQueryOptions() {
    try {
      MaintenanceRequest.availability(parse("{\"selector\":\"username\",\"value\":\"a\",\"first\":0}"));
      fail("Generic native search accepted");
    } catch (WebApplicationException expected) {
      assertEquals(400, expected.getResponse().getStatus());
    }
  }

  @Test
  public void combinedOrdinaryProfileRetainsExactFiniteProfileShape() {
    accepted("ordinary-profile", "{\"group\":\"/human-roles/consultant\",\"profile\":{\"firstName\":\"Reviewed\",\"lastName\":\"Native\",\"email\":\"synthetic@example.invalid\"}}");
    rejected("ordinary-profile", "{\"group\":\"/human-roles/consultant\",\"profile\":{\"firstName\":\"Reviewed\",\"lastName\":\"Native\",\"email\":null,\"roles\":[\"realm-admin\"]}}");
    rejected("ordinary-profile", "{\"group\":\"/human-roles/consultant\",\"profile\":null}");
  }

  @Test
  public void nonsecretFactorProjectionIsAnExplicitClosedHumanAdminRead() {
    var target = parse("{" + TARGET + "}");
    var origin = (com.fasterxml.jackson.databind.node.ObjectNode) target.path("target").path("origin");
    origin.put("kind", "HUMAN_ADMIN"); origin.put("humanAuthority", "PROTECTED_ACCOUNT_OPERATIONS_V1");
    ((com.fasterxml.jackson.databind.node.ObjectNode) target).put("include", "TWO_FACTOR_STATUS_V1");
    try { assertEquals("read", MaintenanceRequest.parse("read", ID, target).command()); }
    catch (WebApplicationException rejected) { fail("Reviewed nonsecret factor projection rejected with status " + rejected.getResponse().getStatus()); }
    for (var invalid : java.util.List.of(JSON.nullNode(), JSON.getNodeFactory().booleanNode(true), JSON.getNodeFactory().numberNode(1), JSON.getNodeFactory().textNode("OTP_SECRET"))) {
      var foreign = target.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode)foreign).set("include", invalid);
      try { MaintenanceRequest.parse("read", ID, foreign); fail("Unreviewed read projection accepted"); }
      catch (WebApplicationException rejected) { assertEquals(400, rejected.getResponse().getStatus()); }
    }
  }

  private static MaintenanceRequest accepted(String operation, String change) {
    try {
      return MaintenanceRequest.parse(operation, ID, parse(command(change)));
    } catch (WebApplicationException rejected) {
      throw new AssertionError("Valid " + operation + " command rejected with status "
          + rejected.getResponse().getStatus());
    }
  }

  private static String command(String change) {
    return "{" + TARGET + ",\"operationId\":\"" + OPERATION + "\","
        + "\"expectedState\":\"" + "a".repeat(64) + "\",\"change\":" + change + "}";
  }

  private static void rejected(String operation, String change) {
    try {
      MaintenanceRequest.parse(operation, ID, parse(command(change)));
      fail("Unbounded maintenance request accepted");
    } catch (WebApplicationException expected) {
      assertTrue(expected.getResponse().getStatus() == 400 || expected.getResponse().getStatus() == 403);
    }
  }
}
