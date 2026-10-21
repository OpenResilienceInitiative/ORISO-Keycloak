package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;

/** Typed untrusted app input only. No parser result conveys native target authority. */
record ScopedOtpRequest(String operation, String accountId, String operationId,
    String expectedState, JsonNode target, JsonNode otp, JsonNode body) {
  static ScopedOtpRequest parse(String operation, String accountId, JsonNode body) {
    // Compiling diagnostic signature; positive wire assertions must fail before decoding is added.
    bad();
    return null;
  }

  @Override public String toString() {
    return "ScopedOtpRequest[operation=" + operation + ", payload=redacted]";
  }
}
