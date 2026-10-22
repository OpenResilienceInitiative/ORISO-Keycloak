package org.oriso.keycloak.lifecycle;

import static org.junit.Assert.*;
import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.WebApplicationException;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

/** Actual shared codec data boundary; successful decoding never supplies authorization. */
public class ScopedOtpRequestTest {
  private static final String ID = "194b23de-93d9-4d1e-990f-4bf4c96b9dd8";
  private static final String OPERATION = "8c038518-f5e2-4557-9fa9-2698286b998c";
  // Pinned HmacOTP.generateSecret uses a raw mixed-case alphanumeric key, then QR encodes it.
  private static final String SECRET = "abcde0189ABCDEFGHIJKLMNOPQRSTUVW";

  @Test
  public void actualAppWireFieldsDecodeWithoutGenericNativeRepresentation() {
    var request = accepted(body());
    assertEquals("otp.app-setup", request.operation());
    assertEquals(ID, request.accountId());
    assertEquals(OPERATION, request.operationId());
    assertEquals("a".repeat(64), request.expectedState());
    assertEquals(SECRET, request.otp().path("secret").asText());
    assertEquals("123456", request.otp().path("initialCode").asText());
    assertEquals(body(), request.body());
  }

  @Test
  public void unknownEnvelopeAndNativeTargetFieldsAreRejected() {
    var extra = body();
    extra.put("enabled", true);
    rejected("otp.app-setup", ID, extra);
    extra = body();
    ((com.fasterxml.jackson.databind.node.ObjectNode) extra.path("target")).put("roles", "realm-admin");
    rejected("otp.app-setup", ID, extra);
  }

  @Test
  public void actualPathAndExactTargetMustMatch() {
    rejected("otp.app-setup", "194b23de-93d9-4d1e-990f-4bf4c96b9dd9", body());
  }

  @Test
  public void appFieldsCannotCarryEmailOrAnUnboundedSecretOrCode() {
    var extra = body();
    ((com.fasterxml.jackson.databind.node.ObjectNode) extra.path("otp")).put("email", "other@test.invalid");
    rejected("otp.app-setup", ID, extra);
    extra = body();
    ((com.fasterxml.jackson.databind.node.ObjectNode) extra.path("otp")).put("secret", "A".repeat(513));
    rejected("otp.app-setup", ID, extra);
    extra = body();
    ((com.fasterxml.jackson.databind.node.ObjectNode) extra.path("otp")).put("initialCode", "123456\n");
    rejected("otp.app-setup", ID, extra);
  }

  @Test
  public void stableOperationAndOpaqueStateAreRequired() {
    var extra = body();
    extra.remove("operationId");
    rejected("otp.app-setup", ID, extra);
    extra = body();
    extra.put("expectedState", "fresh-state-from-session");
    rejected("otp.app-setup", ID, extra);
  }

  @Test
  public void originalStrictJsonRejectsDuplicatesTrailingDataAndInvalidUtf8() {
    rejectedRaw("{\"target\":{},\"target\":{}}".getBytes(StandardCharsets.UTF_8));
    rejectedRaw((canonical(body()) + " {}").getBytes(StandardCharsets.UTF_8));
    rejectedRaw(new byte[] {(byte) 0xc3, (byte) 0x28});
  }

  @Test
  public void onlyTheExplicitImplementedOtpOperationsAreAccepted() {
    rejected("otp.native-proxy", ID, body());
    rejected("otp.*", ID, body());
    rejected("account.password", ID, body());
  }

  @Test
  public void deleteHasExactlyANullOtpPayload() {
    var exact = body();
    exact.putNull("otp");
    var decoded = ScopedOtpRequest.parse("otp.delete", ID, exact);
    assertEquals(OPERATION, decoded.operationId());
    assertTrue(decoded.otp().isNull());
    rejected("otp.delete", ID, body());
  }

  @Test
  public void emailFinishDecodesOnlyTheInitialCodeWithNullSecretAndEmail() {
    var exact = body();
    ((com.fasterxml.jackson.databind.node.ObjectNode) exact.path("otp")).putNull("secret");
    ScopedOtpRequest decoded;
    try {
      decoded = ScopedOtpRequest.parse("otp.email-finish", ID, exact);
    } catch (WebApplicationException rejected) {
      throw new AssertionError("Actual closed initial-code finish body must decode");
    }
    assertEquals("otp.email-finish", decoded.operation());
    assertEquals("123456", decoded.otp().path("initialCode").asText());
    assertTrue(decoded.otp().path("secret").isNull());
    assertTrue(decoded.otp().path("email").isNull());
    rejected("otp.email-finish", ID, body());
    ((com.fasterxml.jackson.databind.node.ObjectNode) exact.path("otp")).put("email", "other@test.invalid");
    rejected("otp.email-finish", ID, exact);
  }

  @Test
  public void emailStartAcceptsOnlyTheBoundedDestinationWithNullCodeAndSecret() {
    var exact = body();
    var otp = (com.fasterxml.jackson.databind.node.ObjectNode) exact.path("otp");
    otp.putNull("initialCode");
    otp.putNull("secret");
    otp.put("email", "pending@test.invalid");
    var decoded = ScopedOtpRequest.parse("otp.email-start", ID, exact);
    assertEquals("pending@test.invalid", decoded.otp().path("email").asText());
    assertFalse(decoded.toString().contains("pending@test.invalid"));
    for (String invalid : new String[] {"", " ", "pending@test.invalid\r\nBcc:x@y.invalid", "x".repeat(321)}) {
      otp.put("email", invalid);
      rejected("otp.email-start", ID, exact);
    }
    otp.put("email", "pending@test.invalid");
    otp.put("secret", SECRET);
    rejected("otp.email-start", ID, exact);
    otp.putNull("secret");
    otp.put("initialCode", "123456");
    rejected("otp.email-start", ID, exact);
    otp.putNull("initialCode");
    otp.put("unreviewed", true);
    rejected("otp.email-start", ID, exact);
  }

  @Test
  public void setupSecretAndInitialCodeCannotAppearInTheRequestDescription() {
    String description = accepted(body()).toString();
    assertFalse(description.contains(SECRET));
    assertFalse(description.contains("123456"));
  }

  private static com.fasterxml.jackson.databind.node.ObjectNode body() {
    var body = JSON.createObjectNode();
    var target = body.putObject("target");
    target.put("accountId", ID);
    target.put("tenantId", "1");
    var origin = target.putObject("origin");
    origin.put("kind", "SELF");
    origin.put("workflowId", "actual-self-intent");
    origin.put("humanSubject", ID);
    origin.put("humanIssuer", "https://auth.test/realms/r");
    origin.put("humanClient", "app");
    origin.putNull("humanAuthority");
    body.put("operationId", OPERATION);
    body.put("expectedState", "a".repeat(64));
    var otp = body.putObject("otp");
    otp.put("initialCode", "123456");
    otp.put("secret", SECRET);
    otp.putNull("email");
    return body;
  }

  private static ScopedOtpRequest accepted(JsonNode body) {
    try {
      return ScopedOtpRequest.parse("otp.app-setup", ID, body);
    } catch (WebApplicationException rejected) {
      throw new AssertionError("Exact app wire rejected with status " + rejected.getResponse().getStatus());
    }
  }

  private static void rejected(String operation, String account, JsonNode body) {
    try {
      ScopedOtpRequest.parse(operation, account, body);
      fail("Unbounded OTP input accepted");
    } catch (WebApplicationException rejected) {
      assertTrue(rejected.getResponse().getStatus() == 400 || rejected.getResponse().getStatus() == 403);
    }
  }

  private static void rejectedRaw(byte[] raw) {
    try {
      ScopedOtpRequest.parse("otp.app-setup", ID, LifecycleJson.parse(raw));
      fail("Invalid OTP JSON accepted");
    } catch (WebApplicationException rejected) {
      assertEquals(400, rejected.getResponse().getStatus());
    }
  }
}
