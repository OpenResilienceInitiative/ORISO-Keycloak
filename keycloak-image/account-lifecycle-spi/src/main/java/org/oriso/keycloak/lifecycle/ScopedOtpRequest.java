package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;

/** Typed untrusted app input only. No parser result conveys native target authority. */
record ScopedOtpRequest(String operation, String accountId, String operationId,
    String expectedState, JsonNode target, JsonNode otp, JsonNode body) {
  static ScopedOtpRequest parse(String operation, String accountId, JsonNode body) {
    if (!java.util.Set.of("otp.app-setup", "otp.delete", "otp.email-finish", "otp.email-start").contains(operation)) deny();
    uuid(accountId);
    if ("otp.email-start".equals(operation))
      fields(body, "target", "operationId", "expectedState", "otp", "authorityValidUntil");
    else fields(body, "target", "operationId", "expectedState", "otp");
    var read = JSON.createObjectNode();
    read.set("target", body.path("target"));
    var checkedTarget = MaintenanceRequest.parse("read", accountId, read).target();
    String operationId = uuid(text(body, "operationId", 36, false));
    String state = text(body, "expectedState", 64, false);
    hex(state);
    var otp = body.path("otp");
    if ("otp.delete".equals(operation)) {
      if (!otp.isNull()) bad();
      return new ScopedOtpRequest(operation, accountId, operationId, state,
          checkedTarget.deepCopy(), otp.deepCopy(), body.deepCopy());
    }
    fields(otp, "initialCode", "secret", "email");
    if ("otp.email-start".equals(operation)) {
      var deadline = body.path("authorityValidUntil");
      if (!deadline.isIntegralNumber() || !deadline.canConvertToLong() || deadline.longValue() <= 0) bad();
      String email = text(otp, "email", 320, false);
      if (!otp.path("initialCode").isNull() || !otp.path("secret").isNull()
          || !email.equals(email.strip()) || email.chars().anyMatch(c -> c < 33 || c == 127)
          || !email.matches("[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")) bad();
      return new ScopedOtpRequest(operation, accountId, operationId, state,
          checkedTarget.deepCopy(), otp.deepCopy(), body.deepCopy());
    }
    String initialCode = text(otp, "initialCode", 8, false);
    boolean finish = "otp.email-finish".equals(operation);
    String secret = text(otp, "secret", 512, finish);
    if (!initialCode.matches("[0-9]{6,8}") || !otp.path("email").isNull()
        || finish && !otp.path("secret").isNull()
        || !finish && !secret.matches("[A-Za-z0-9]{16,512}")) bad();
    return new ScopedOtpRequest(operation, accountId, operationId, state,
        checkedTarget.deepCopy(), otp.deepCopy(), body.deepCopy());
  }

  @Override public String toString() {
    return "ScopedOtpRequest[operation=" + operation + ", payload=redacted]";
  }
}
