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
  public void invitationEmailReadHasClosedNormalizedSelectorsWithoutAccountDisclosure() {
    var value = invitationEmail();
    assertEquals("recipient@example.invalid", InvitationEmailAvailability.parse(value).email());
    for (String field : java.util.List.of("email", "profile", "tenantId", "tenantMode", "origin")) {
      var missing = value.deepCopy(); missing.remove(field);
      assertThrows(WebApplicationException.class, () -> InvitationEmailAvailability.parse(missing));
    }
    for (String field : java.util.List.of("accountId", "excludedAccountId", "username", "emailVerified")) {
      var extra = value.deepCopy(); extra.put(field, ID);
      assertThrows(WebApplicationException.class, () -> InvitationEmailAvailability.parse(extra));
    }
    for (String email : java.util.List.of("Recipient@example.invalid", " recipient@example.invalid", "bad", "a\nb@example.invalid")) {
      var wrong = value.deepCopy(); wrong.put("email", email);
      assertThrows(WebApplicationException.class, () -> InvitationEmailAvailability.parse(wrong));
    }
    var secret = value.deepCopy(); secret.put("email", "recipient@example.invalid");
    assertFalse(InvitationEmailAvailability.parse(secret).toString().contains("recipient"));
    // A real receiver infrastructure failure cannot become an available recipient or reach user lookup.
    var rolledBack = new java.util.concurrent.atomic.AtomicBoolean();
    var transactions = (org.keycloak.models.KeycloakTransactionManager) java.lang.reflect.Proxy.newProxyInstance(
        getClass().getClassLoader(), new Class<?>[] {org.keycloak.models.KeycloakTransactionManager.class},
        (proxy, method, args) -> { if (method.getName().equals("setRollbackOnly")) { rolledBack.set(true); return null; }
          throw new AssertionError("Unexpected transaction call"); });
    var session = (org.keycloak.models.KeycloakSession) java.lang.reflect.Proxy.newProxyInstance(
        getClass().getClassLoader(), new Class<?>[] {org.keycloak.models.KeycloakSession.class},
        (proxy, method, args) -> {
          if (method.getName().equals("getTransactionManager")) return transactions;
          if (method.getName().equals("getContext")) throw new IllegalStateException("fixture unavailable");
          throw new AssertionError("No user lookup or other native call before authentication");
        });
    var auth = new LifecycleAuthorization("r", ID, OPERATION, new byte[32], "fixture-key");
    var receiver = new AccountMaintenanceResource(session, auth, java.util.Map.of(), () -> { throw new AssertionError("No policy bypass"); });
    var unavailable = assertThrows(WebApplicationException.class,
        () -> receiver.invitationEmailAvailability(canonical(value).getBytes(java.nio.charset.StandardCharsets.UTF_8), "invalid", null));
    assertEquals(503, unavailable.getResponse().getStatus());
    assertEquals("no-store", unavailable.getResponse().getHeaderString("Cache-Control"));
    assertTrue(rolledBack.get());
    assertFalse(((java.util.Map<?, ?>) unavailable.getResponse().getEntity()).containsKey("available"));
  }

  @Test
  public void invitationEmailReadKeepsExactProfileTenantAndHumanShape() {
    var value = invitationEmail();
    for (String mode : java.util.List.of("RESERVED_NEW", "UNASSIGNED")) {
      var waiting = value.deepCopy(); waiting.putNull("tenantId"); waiting.put("tenantMode", mode);
      assertNull(InvitationEmailAvailability.parse(waiting).tenantId());
    }
    for (String tenant : java.util.List.of("", "01", "-1", "9223372036854775808")) {
      var wrong = value.deepCopy(); wrong.put("tenantId", tenant);
      assertThrows(WebApplicationException.class, () -> InvitationEmailAvailability.parse(wrong));
    }
    var nullExisting = value.deepCopy(); nullExisting.putNull("tenantId");
    assertThrows(WebApplicationException.class, () -> InvitationEmailAvailability.parse(nullExisting));
    for (String kind : java.util.List.of("SELF", "INVITATION", "IMPORT")) {
      var wrong = value.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) wrong.path("origin")).put("kind", kind);
      assertThrows(WebApplicationException.class, () -> InvitationEmailAvailability.parse(wrong));
    }
    var foreign = value.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode) foreign.path("profile")).put("kind", "PLATFORM_ADMIN");
    assertThrows(WebApplicationException.class, () -> InvitationEmailAvailability.parse(foreign));
  }

  private static com.fasterxml.jackson.databind.node.ObjectNode invitationEmail() {
    var body = JSON.createObjectNode(); body.put("email", "recipient@example.invalid");
    body.put("tenantId", "17"); body.put("tenantMode", "EXISTING");
    body.putObject("profile").put("family", "ORDINARY").put("id", "consultant-v1").put("version", 1).put("kind", "CONSULTANT");
    body.putObject("origin").put("kind", "HUMAN_ADMIN").put("workflowId", "invitation-email-preflight")
        .put("humanSubject", ID).put("humanIssuer", "https://auth.test/realms/r").put("humanClient", "admin")
        .put("humanAuthority", "PROTECTED_ACCOUNT_OPERATIONS_V1");
    return body;
  }

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
    accepted("email", "{\"email\":\"owned@example.invalid\"}");
    accepted("email", "{\"firstName\":null,\"lastName\":\"Owned\",\"email\":\"owned@example.invalid\"}");
    for(String invalid:java.util.List.of("{\"firstName\":\"Owned\",\"email\":\"owned@example.invalid\"}",
        "{\"firstName\":1,\"lastName\":\"Owned\",\"email\":\"owned@example.invalid\"}",
        "{\"firstName\":\"Owned\",\"lastName\":\"Self\",\"email\":null}",
        "{\"firstName\":\"Owned\",\"lastName\":\"Self\",\"email\":\"owned@example.invalid\",\"emailVerified\":true}"))rejected("email",invalid);
    var human=(com.fasterxml.jackson.databind.node.ObjectNode)parse(command("{\"firstName\":\"Owned\",\"lastName\":\"Self\",\"email\":\"owned@example.invalid\"}"));
    var origin=(com.fasterxml.jackson.databind.node.ObjectNode)human.path("target").path("origin");
    origin.put("kind","HUMAN_ADMIN");origin.put("humanAuthority","PROTECTED_ACCOUNT_OPERATIONS_V1");
    try{MaintenanceRequest.parse("email",ID,human);fail("Combined email is confined to actual SELF");}
    catch(WebApplicationException expected){assertEquals(400,expected.getResponse().getStatus());}
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
  public void contactEmailMayOnlyPreserveTheActualSelfVerificationState() {
    var change = accepted("email", "{\"email\":\"contact@example.invalid\",\"preserveEmailVerified\":true}");
    assertTrue(change.change().path("preserveEmailVerified").booleanValue());
    for (String invalid : java.util.List.of(
        "{\"email\":\"contact@example.invalid\",\"preserveEmailVerified\":false}",
        "{\"email\":\"contact@example.invalid\",\"preserveEmailVerified\":\"true\"}",
        "{\"email\":\"contact@example.invalid\",\"preserveEmailVerified\":true,\"emailVerified\":true}",
        "{\"email\":\"contact@example.invalid\",\"preserveEmailVerified\":true,\"firstName\":\"Other\"}")) {
      rejected("email", invalid);
    }
    var foreign = (com.fasterxml.jackson.databind.node.ObjectNode)parse(command(
        "{\"email\":\"contact@example.invalid\",\"preserveEmailVerified\":true}"));
    var origin = (com.fasterxml.jackson.databind.node.ObjectNode)foreign.path("target").path("origin");
    origin.put("kind", "HUMAN_ADMIN");
    origin.put("humanAuthority", "PROTECTED_ACCOUNT_OPERATIONS_V1");
    try {
      MaintenanceRequest.parse("email", ID, foreign);
      fail("Contact-email preservation is confined to actual SELF");
    } catch (WebApplicationException expected) {
      assertEquals(400, expected.getResponse().getStatus());
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
  public void ordinarySelfConsultantGrantHasOnlyTheExistingGroupTransitionShape() {
    var body=parse("{" + TARGET + ",\"operationId\":\"22222222-2222-4222-8222-222222222222\",\"expectedState\":\"" + "a".repeat(64) + "\",\"change\":{\"transition\":\"ADD_CONSULTANT_IDENTITY\",\"group\":\"/human-roles/consultant-agency-admin\"}}");
    var origin=(com.fasterxml.jackson.databind.node.ObjectNode)body.path("target").path("origin");
    origin.put("kind","HUMAN_ADMIN");origin.put("humanAuthority","ORDINARY_ACCOUNT_OPERATIONS_V1");
    try { assertEquals("profile-transition",MaintenanceRequest.parse("profile-transition",ID,body).command()); }
    catch(WebApplicationException refused){fail("Reviewed ordinary own Consultant grant shape refused with status "+refused.getResponse().getStatus());}
    for(String transition:java.util.List.of("ADD_AGENCY_ADMIN_IDENTITY","REMOVE_ADMINISTRATOR_IDENTITY")){
      var wrong=body.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)wrong.path("change")).put("transition",transition);
      try{MaintenanceRequest.parse("profile-transition",ID,wrong);fail("Unreviewed ordinary identity transition accepted");}
      catch(WebApplicationException refused){assertEquals(403,refused.getResponse().getStatus());}
    }
  }

  @Test
  public void nonsecretFactorProjectionIsAnExplicitClosedHumanAdminRead() {
    var target = parse("{" + TARGET + "}");
    var origin = (com.fasterxml.jackson.databind.node.ObjectNode) target.path("target").path("origin");
    origin.put("kind", "HUMAN_ADMIN"); origin.put("humanAuthority", "PROTECTED_ACCOUNT_OPERATIONS_V1");
    ((com.fasterxml.jackson.databind.node.ObjectNode) target).put("include", "TWO_FACTOR_STATUS_V1");
    try { assertEquals("read", MaintenanceRequest.parse("read", ID, target).command()); }
    catch (WebApplicationException rejected) { fail("Reviewed nonsecret factor projection rejected with status " + rejected.getResponse().getStatus()); }
    origin.put("humanAuthority", "ORDINARY_ACCOUNT_OPERATIONS_V1");
    try { assertEquals("read", MaintenanceRequest.parse("read", ID, target).command()); }
    catch (WebApplicationException rejected) { fail("Reviewed ordinary nonsecret factor projection rejected with status " + rejected.getResponse().getStatus()); }
    var foreignAuthority = target.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode) foreignAuthority.path("target").path("origin")).put("humanAuthority", "UNREVIEWED");
    try { MaintenanceRequest.parse("read", ID, foreignAuthority); fail("Unreviewed authority read projection accepted"); }
    catch (WebApplicationException rejected) { assertEquals(400, rejected.getResponse().getStatus()); }
    for (var invalid : java.util.List.of(JSON.nullNode(), JSON.getNodeFactory().booleanNode(true), JSON.getNodeFactory().numberNode(1), JSON.getNodeFactory().textNode("OTP_SECRET"))) {
      var foreign = target.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode)foreign).set("include", invalid);
      try { MaintenanceRequest.parse("read", ID, foreign); fail("Unreviewed read projection accepted"); }
      catch (WebApplicationException rejected) { assertEquals(400, rejected.getResponse().getStatus()); }
    }
  }

  @Test
  public void tenantReassignmentIsAnExactPositiveDesiredTenantAssertion() {
    accepted("reassign-tenant", "{\"tenantId\":\"2\"}");
    for (String change : java.util.List.of("{\"tenantId\":\"0\"}", "{\"tenantId\":2}", "{\"tenantId\":null}", "{\"tenantId\":\"2\",\"roles\":[]}")) rejected("reassign-tenant", change);
  }

  @Test
  public void inactivityWorkflowRetainsOriginalSignedLongRevisionAndFiniteAction() {
    var body = (com.fasterxml.jackson.databind.node.ObjectNode) parse(command("{}"));
    var origin = (com.fasterxml.jackson.databind.node.ObjectNode)body.path("target").path("origin");
    origin.put("kind", "INACTIVITY"); origin.put("workflowId", OPERATION);
    for (String key : java.util.List.of("humanSubject", "humanIssuer", "humanClient", "humanAuthority")) origin.putNull(key);
    var workflow=body.putObject("workflow"); workflow.put("v",1); workflow.put("kind","INACTIVITY"); workflow.put("workId",OPERATION);
    workflow.put("action","SUSPEND"); workflow.put("rowDigest","b".repeat(64)); workflow.put("revision",0);
    workflow.put("assignedMonths",24); workflow.put("lastActivity",1); workflow.put("dueAt",2); workflow.putNull("suspensionOperationId");
    try { MaintenanceRequest.parse("deactivate", ID, body); }
    catch (WebApplicationException refused) { fail("Reviewed bootstrap inactivity workflow rejected with status " + refused.getResponse().getStatus()); }
    workflow.put("revision",Long.MAX_VALUE); MaintenanceRequest.parse("deactivate",ID,body);
    for (var invalid : java.util.List.of(JSON.getNodeFactory().numberNode(-1), JSON.getNodeFactory().numberNode(new java.math.BigInteger("9223372036854775808")), JSON.getNodeFactory().textNode("0"))) {
      var wrong=body.deepCopy(); ((com.fasterxml.jackson.databind.node.ObjectNode)wrong.path("workflow")).set("revision",invalid);
      try { MaintenanceRequest.parse("deactivate",ID,wrong); fail("Invalid revision accepted"); } catch (WebApplicationException expected) { assertEquals(400,expected.getResponse().getStatus()); }
    }
  }

  @Test
  public void typedProfileTransitionHasOnlyTwoFiniteHumanSelectorShapes() {
    var body = (com.fasterxml.jackson.databind.node.ObjectNode) parse(command("{}"));
    var origin = (com.fasterxml.jackson.databind.node.ObjectNode) body.path("target").path("origin");
    origin.put("kind", "HUMAN_ADMIN"); origin.put("humanAuthority", "PROTECTED_ACCOUNT_OPERATIONS_V1");
    for (String transition : java.util.List.of("ADD_CONSULTANT_IDENTITY", "ADD_AGENCY_ADMIN_IDENTITY")) {
      for (String selector : java.util.List.of("{\"group\":\"/human-roles/consultant-agency-admin\"}",
          "{\"profileId\":\"reviewed-tenant-dual-v2\",\"profileVersion\":2}")) {
        var change=(com.fasterxml.jackson.databind.node.ObjectNode)parse(selector);change.put("transition",transition);body.set("change",change);
        try { assertEquals(transition,MaintenanceRequest.parse("profile-transition",ID,body).change().path("transition").asText()); }
        catch(WebApplicationException refused){fail("Reviewed typed profile transition rejected with status "+refused.getResponse().getStatus());}
      }
    }
    for (String invalid : java.util.List.of("{\"transition\":\"REMOVE_UNKNOWN_IDENTITY\",\"group\":\"/human-roles/consultant\"}",
        "{\"transition\":\"ADD_CONSULTANT_IDENTITY\",\"roles\":[\"consultant\"]}",
        "{\"transition\":\"ADD_CONSULTANT_IDENTITY\",\"group\":\"/human-roles/consultant\",\"profileId\":\"dual\",\"profileVersion\":1}",
        "{\"transition\":\"ADD_CONSULTANT_IDENTITY\",\"profileId\":\"dual\",\"profileVersion\":0}",
        "{\"transition\":\"ADD_CONSULTANT_IDENTITY\",\"profileId\":\"dual\",\"profileVersion\":\"1\"}")) {
      body.set("change",parse(invalid));
      try{MaintenanceRequest.parse("profile-transition",ID,body);fail("Unreviewed transition accepted");}
      catch(WebApplicationException expected){assertEquals(400,expected.getResponse().getStatus());}
    }
    body.set("change",parse("{\"transition\":\"ADD_CONSULTANT_IDENTITY\",\"group\":\"/human-roles/consultant\"}"));
    origin.put("kind","SELF");
    try{MaintenanceRequest.parse("profile-transition",ID,body);fail("SELF cannot select a typed administration transition");}
    catch(WebApplicationException expected){assertTrue(expected.getResponse().getStatus()==400||expected.getResponse().getStatus()==403);}
  }

  @Test
  public void existingConsultantImportWorkflowIsExactSevenFieldsAndClosedRequiredRoles() {
    var body=(com.fasterxml.jackson.databind.node.ObjectNode)parse(command("{\"group\":\"/human-roles/consultant-agency-admin\"}"));
    var origin=(com.fasterxml.jackson.databind.node.ObjectNode)body.path("target").path("origin");
    origin.put("kind","IMPORT");origin.put("workflowId",OPERATION);
    for(String key:java.util.List.of("humanSubject","humanIssuer","humanClient","humanAuthority"))origin.putNull(key);
    var workflow=body.putObject("workflow");workflow.put("v",1);workflow.put("kind","IMPORT");workflow.put("workId",OPERATION);
    workflow.put("sourceDigest","a".repeat(64));workflow.put("recordNumber",Long.MAX_VALUE);workflow.put("rowDigest","b".repeat(64));
    workflow.putArray("requiredRoles").add("consultant").add("restricted-agency-admin").add("user-admin");
    try{assertEquals("IMPORT",MaintenanceRequest.parse("ordinary-profile",ID,body).workflow().path("kind").asText());}
    catch(WebApplicationException refused){fail("Reviewed exact existing import workflow rejected with status "+refused.getResponse().getStatus());}
    for(String roles:java.util.List.of("[]","[\"consultant\",\"consultant\"]","[\"user\"]","[\"realm-admin\",\"consultant\"]","[\"user-admin\",\"consultant\"]")){
      var wrong=body.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)wrong.path("workflow")).set("requiredRoles",parse("{\"roles\":"+roles+"}").path("roles"));
      try{MaintenanceRequest.parse("ordinary-profile",ID,wrong);fail("Unreviewed import role tuple accepted");}
      catch(WebApplicationException expected){assertEquals(400,expected.getResponse().getStatus());}
    }
    for(String field:java.util.List.of("v","kind","workId","sourceDigest","recordNumber","rowDigest","requiredRoles")){
      var wrong=body.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)wrong.path("workflow")).remove(field);
      try{MaintenanceRequest.parse("ordinary-profile",ID,wrong);fail("Incomplete import tuple accepted");}
      catch(WebApplicationException expected){assertEquals(400,expected.getResponse().getStatus());}
    }
    var extra=body.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)extra.path("workflow")).put("humanAuthority","PLATFORM");
    try{MaintenanceRequest.parse("ordinary-profile",ID,extra);fail("Unreviewed import field accepted");}
    catch(WebApplicationException expected){assertEquals(400,expected.getResponse().getStatus());}
    for(String command:java.util.List.of("deactivate","reactivate","profile-transition","delete")){
      try{MaintenanceRequest.parse(command,ID,body);fail("Import workflow granted unrelated command");}
      catch(WebApplicationException expected){assertTrue(expected.getResponse().getStatus()==400||expected.getResponse().getStatus()==403);}
    }
  }

  @Test
  public void actualSecretFieldsPreserveOpaqueControlsAndWhitespace() {
    for (String secret : java.util.List.of("opaque\nvalue", "\t", "   ")) {
      for (String operation : java.util.List.of("password", "self-password", "reactivate")) {
        var change = JSON.createObjectNode().put("password", secret);
        if (operation.equals("reactivate")) change.put("expectedUsername", "original").put("expectedEmail", "original@example.invalid");
        else change.put("temporary", false);
        if (operation.equals("self-password")) change.put("currentPassword", "original-" + secret);
        var result = accepted(operation, canonical(change));
        assertEquals(secret, result.change().path("password").textValue());
        if (operation.equals("self-password")) assertEquals("original-" + secret, result.change().path("currentPassword").textValue());
        assertFalse(result.toString().contains("opaque"));
      }
    }
  }

  @Test
  public void opaqueSecretBoundsDoNotRelaxAnyIdentifierOrSecretType() {
    for (String operation : java.util.List.of("password", "self-password", "reactivate")) {
      for (var bad : java.util.List.of(JSON.nullNode(), JSON.valueToTree(7), JSON.valueToTree(""), JSON.valueToTree("x".repeat(4097)))) {
        var change = JSON.createObjectNode(); change.set("password", bad);
        if (operation.equals("reactivate")) change.put("expectedUsername", "original").put("expectedEmail", "original@example.invalid");
        else change.put("temporary", false);
        if (operation.equals("self-password")) change.put("currentPassword", "original");
        rejected(operation, canonical(change));
      }
    }
    rejected("reactivate", canonical(JSON.createObjectNode().put("expectedUsername", "invalid\nname").put("expectedEmail", "original@example.invalid").put("password", "valid")));
    rejected("locale", canonical(JSON.createObjectNode().put("locale", "\t")));
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
  @Test public void consultantRemovalHasOnlyFixedOrdinaryOrProtectedSelectors(){
    for(String authority:java.util.List.of("ORDINARY_ACCOUNT_OPERATIONS_V1","PROTECTED_ACCOUNT_OPERATIONS_V1")){
      var body=(com.fasterxml.jackson.databind.node.ObjectNode)parse(command("{\"transition\":\"REMOVE_CONSULTANT_IDENTITY\",\"group\":\"/human-roles/agency-admin\"}"));
      var origin=(com.fasterxml.jackson.databind.node.ObjectNode)body.path("target").path("origin");
      origin.put("kind","HUMAN_ADMIN");origin.put("humanAuthority",authority);
      origin.put("humanSubject","33333333-3333-4333-8333-333333333333");
      try{assertEquals("REMOVE_CONSULTANT_IDENTITY",MaintenanceRequest.parse("profile-transition",ID,body).change().path("transition").asText());}
      catch(WebApplicationException rejected){fail("Fixed Consultant-only removal rejected: "+rejected.getResponse().getStatus());}
      ((com.fasterxml.jackson.databind.node.ObjectNode)body.path("change")).put("roles","arbitrary");
      assertThrows(WebApplicationException.class,()->MaintenanceRequest.parse("profile-transition",ID,body));
    }
    var body=(com.fasterxml.jackson.databind.node.ObjectNode)parse(command("{\"transition\":\"REMOVE_CONSULTANT_IDENTITY\",\"profileId\":\"tenant-pure-v1\",\"profileVersion\":1}"));
    var origin=(com.fasterxml.jackson.databind.node.ObjectNode)body.path("target").path("origin");
    origin.put("kind","HUMAN_ADMIN");origin.put("humanAuthority","PROTECTED_ACCOUNT_OPERATIONS_V1");
    try{assertEquals("profile-transition",MaintenanceRequest.parse("profile-transition",ID,body).command());}
    catch(WebApplicationException rejected){fail("Fixed protected Consultant-only removal rejected: "+rejected.getResponse().getStatus());}
    origin.put("humanAuthority","ORDINARY_ACCOUNT_OPERATIONS_V1");
    assertThrows(WebApplicationException.class,()->MaintenanceRequest.parse("profile-transition",ID,body));
  }
}
