package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;

/** Typed untrusted app input only. No parser result conveys native target authority. */
record ScopedOtpRequest(String operation, String accountId, String operationId,
    String expectedState, JsonNode target, JsonNode otp, JsonNode body) {
  static ScopedOtpRequest parse(String operation, String accountId, JsonNode body) {
    if (!"otp.app-setup".equals(operation)) deny();
    uuid(accountId);
    fields(body, "target", "operationId", "expectedState", "otp");
    var read = JSON.createObjectNode();
    read.set("target", body.path("target"));
    var checkedTarget = MaintenanceRequest.parse("read", accountId, read).target();
    String operationId = uuid(text(body, "operationId", 36, false));
    String state = text(body, "expectedState", 64, false);
    hex(state);
    var otp = body.path("otp");
    fields(otp, "initialCode", "secret", "email");
    String initialCode = text(otp, "initialCode", 8, false);
    String secret = text(otp, "secret", 512, false);
    if (!initialCode.matches("[0-9]{6,8}") || !secret.matches("[A-Za-z0-9]{16,512}")
        || !otp.path("email").isNull()) bad();
    return new ScopedOtpRequest(operation, accountId, operationId, state,
        checkedTarget.deepCopy(), otp.deepCopy(), body.deepCopy());
  }

  @Override public String toString() {
    return "ScopedOtpRequest[operation=" + operation + ", payload=redacted]";
  }
}
