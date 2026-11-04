package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Set;

/** Closed causal assertions. Only the checked fixed native route can use these facts. */
final class CausalPasswordRequest {
  private final MaintenanceRequest target;
  private final JsonNode workflow;
  private CausalPasswordRequest(MaintenanceRequest target, JsonNode workflow) {
    this.target = target; this.workflow = workflow.deepCopy();
  }
  static CausalPasswordRequest read(String account, JsonNode body) {
    fields(body, "target", "workflow");
    var selection = JSON.createObjectNode(); selection.set("target", body.path("target"));
    var target = MaintenanceRequest.parse("read", account, selection);
    if (!"PASSWORD_RESET".equals(target.target().path("origin").path("kind").asText())) deny();
    uuid(text(target.target().path("origin"), "workflowId", 36, false));
    var workflow = body.path("workflow");
    fields(workflow, "v", "kind", "claimId", "claimVersion", "authorityValidUntil", "expectedUsername",
        "expectedEmailDigest", "profileKind", "profileId", "profileVersion");
    if (number(workflow, "v", true) != 1 || !Set.of("EXISTING_SETUP", "PASSWORD_RESET").contains(text(workflow, "kind", 20, false))
        || !Set.of("ORDINARY", "PROTECTED").contains(text(workflow, "profileKind", 20, false))) bad();
    uuid(text(workflow, "claimId", 36, false)); number(workflow, "claimVersion", true);
    number(workflow, "authorityValidUntil", true); text(workflow, "expectedUsername", 255, false);
    hex(text(workflow, "expectedEmailDigest", 64, false)); text(workflow, "profileId", 255, false);
    number(workflow, "profileVersion", true);
    return new CausalPasswordRequest(target, workflow);
  }
  static CausalPasswordRequest mutation(String account, JsonNode body) {
    fields(body, "target", "workflow", "operationId", "expectedState", "change");
    var read = JSON.createObjectNode(); read.set("target", body.path("target")); read.set("workflow", body.path("workflow"));
    var causal = read(account, read);
    var mutation = JSON.createObjectNode();
    for (String key : java.util.List.of("target", "operationId", "expectedState", "change")) mutation.set(key, body.path(key));
    var parsed = MaintenanceRequest.parse("password", account, mutation);
    if (parsed.change().path("temporary").asBoolean()) bad();
    causal.command = new MaintenanceRequest("password-reset", account, parsed.target(), parsed.operationId(),
        parsed.expectedState(), parsed.change(), causal.workflow.path("authorityValidUntil").longValue(), null, null);
    return causal;
  }
  private MaintenanceRequest command;
  MaintenanceRequest target() { return target; }
  MaintenanceRequest command() { if (command == null) throw new IllegalStateException(); return command; }
  JsonNode workflow() { return workflow.deepCopy(); }
  void requireLive() {
    if (workflow.path("authorityValidUntil").longValue() <= java.time.Instant.now().getEpochSecond())
      throw new jakarta.ws.rs.BadRequestException("Causal password authority expired");
  }
  void requireProfile(String kind, String id, long version) {
    if (!kind.equals(workflow.path("profileKind").asText()) || !id.equals(workflow.path("profileId").asText())
        || version != workflow.path("profileVersion").longValue()) deny();
  }
  void requireNativeBinding(LifecycleAuthorization crypto, JsonNode current) {
    if (!workflow.path("expectedUsername").asText().equalsIgnoreCase(current.path("username").asText())
        || !current.path("email").isTextual() || current.path("email").asText().isBlank()
        || !LifecycleAuthorization.equal(workflow.path("expectedEmailDigest").asText(),
            crypto.mac("maintenance-workflow-email/v1", current.path("email")))) deny();
    if ("EXISTING_SETUP".equals(workflow.path("kind").asText())) {
      boolean found = false;
      for (var action : current.path("requiredActions")) if ("UPDATE_PASSWORD".equals(action.asText())) found = true;
      if (!found) deny();
    }
  }
  @Override public String toString() { return "CausalPasswordRequest[redacted]"; }
}
