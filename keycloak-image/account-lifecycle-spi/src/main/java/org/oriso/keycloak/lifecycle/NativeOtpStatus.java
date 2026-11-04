package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;

/** Non-secret facts from the same current locking credential projection used by CAS. */
final class NativeOtpStatus {
  static JsonNode read(JsonNode current) {
    boolean configured = false, active = false;
    for (var credential : current.path("credentials")) {
      if (!credential.isArray() || credential.size() != 9) deny();
      String type = credential.path(1).asText();
      if ("otp".equals(type)) {
        // Keycloak's native OTP provider considers a stored OTP credential configured.
        // Credential material remains entirely inside this checked native transaction.
        if (!credential.path(2).isTextual() || !credential.path(3).isTextual()) deny();
        configured = true; active = true;
      } else if ("MAIL_OTP_CM".equals(type)) {
        var data = parse(credential.path(2).asText());
        if (!data.path("active").isBoolean() || !data.path("ttlInSeconds").isIntegralNumber()
            || data.path("ttlInSeconds").longValue() <= 0
            || !data.path("email").isTextual() || data.path("email").asText().isBlank()
            || !data.path("failedVerifications").isIntegralNumber()
            || data.path("failedVerifications").longValue() < 0) deny();
        configured = true; active |= data.path("active").booleanValue();
      }
    }
    var result = JSON.createObjectNode(); result.put("configured", configured); result.put("active", active);
    return result;
  }
  private NativeOtpStatus() {}
}
