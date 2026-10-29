package org.oriso.keycloak.lifecycle;

import static org.junit.Assert.*;

import jakarta.ws.rs.BadRequestException;
import org.junit.Test;

public class LifecycleJsonTest {
  @Test
  public void recursiveCanonicalizationPreservesNullBooleanIntegerAndArrayOrder() {
    assertEquals(
        "{\"a\":[2,1],\"z\":{\"b\":null,\"c\":false}}",
        LifecycleJson.canonical(
            LifecycleJson.parse("{\"z\":{\"c\":false,\"b\":null},\"a\":[2,1]}")));
  }

  @Test(expected = BadRequestException.class)
  public void duplicateKeysCannotChangeSignedMeaning() {
    LifecycleJson.parse("{\"scope\":1,\"scope\":2}");
  }

  @Test(expected = BadRequestException.class)
  public void floatsAreNotCanonicalProtocolNumbers() {
    LifecycleJson.parse("{\"generation\":0.5}");
  }

  @Test(expected = BadRequestException.class)
  public void arraysAreNotCommandObjects() {
    LifecycleJson.parse("[]");
  }

  @Test(expected = BadRequestException.class)
  public void stringGenerationCannotBecomeNumber() {
    LifecycleJson.number(LifecycleJson.parse("{\"generation\":\"0\"}"), "generation", false);
  }

  @Test(expected = BadRequestException.class)
  public void negativeGenerationCannotTakeOver() {
    LifecycleJson.number(LifecycleJson.parse("{\"generation\":-1}"), "generation", false);
  }

  @Test(expected = BadRequestException.class)
  public void unknownKeysCannotEscapeSchema() {
    LifecycleJson.fields(LifecycleJson.parse("{\"id\":1,\"enabled\":true}"), "id");
  }

  @Test(expected = BadRequestException.class)
  public void noncanonicalUuidCannotAliasAttempt() {
    LifecycleJson.uuid("00000000-0000-0000-0000-00000000000A");
  }

  @Test(expected = BadRequestException.class)
  public void bodySizeIsBounded() {
    LifecycleJson.parse("{\"x\":\"" + "x".repeat(65536) + "\"}");
  }

  @Test
  public void optionalChatRoleIsNeverDroppedFromReviewedCombination() {
    assertEquals(
        "CONSULTANT",
        LifecycleGroups.allowedKind(java.util.Set.of("consultant", "group-chat-consultant")));
    assertNull(LifecycleGroups.allowedKind(java.util.Set.of("group-chat-consultant")));
  }

  @Test
  public void combinedCentreRoleSetIsOrdinaryButProtectedRoleIsNot() {
    assertEquals(
        "CONSULTANT_AGENCY_ADMIN",
        LifecycleGroups.allowedKind(
            java.util.Set.of(
                "consultant", "group-chat-consultant", "restricted-agency-admin", "user-admin")));
    assertNull(LifecycleGroups.allowedKind(java.util.Set.of("consultant", "tenant-admin")));
  }

  @Test
  public void creationReceiptMatchesIndependentPythonCanonicalVector() throws Exception {
    var vector =
        LifecycleJson.JSON.readTree(
            getClass().getResourceAsStream("/creation-receipt-vector.json"));
    var key = java.util.HexFormat.of().parseHex(vector.path("testKeyHex").asText());
    var auth =
        new LifecycleAuthorization(
            "fixture", "creator", "admin", key, java.util.Base64.getEncoder().encodeToString(key));
    assertEquals(
        vector.path("creationProof").asText(), auth.creationReceipt(vector.path("payload")));
    assertEquals(
        vector.path("payload").path("initialRoleFingerprint").asText(),
        auth.mac("initial-roles", vector.path("roles")));
  }

  @Test
  public void sharedCallerCreationReceiptVectorMatchesExactly() throws Exception {
    var vector =
        LifecycleJson.JSON.readTree(getClass().getResourceAsStream("/creation-proof-v1.json"));
    var key = java.util.HexFormat.of().parseHex(vector.path("keyHex").asText());
    var auth =
        new LifecycleAuthorization(
            "synthetic",
            "creator",
            "admin",
            key,
            java.util.Base64.getEncoder().encodeToString(key));
    assertEquals(
        vector.path("canonicalPayload").asText(), LifecycleJson.canonical(vector.path("payload")));
    assertEquals(vector.path("proof").asText(), auth.creationReceipt(vector.path("payload")));
    assertEquals(
        vector.path("payload").path("initialRoleFingerprint").asText(),
        auth.mac("initial-roles", vector.path("initialRoles")));
  }
}
