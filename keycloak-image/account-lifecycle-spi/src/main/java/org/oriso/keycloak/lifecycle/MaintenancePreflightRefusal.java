package org.oriso.keycloak.lifecycle;

/** Authenticated finite intent, definitely rejected before its first native write. */
final class MaintenancePreflightRefusal extends jakarta.ws.rs.WebApplicationException {
  private MaintenancePreflightRefusal(int status) { super(status); }
  static MaintenancePreflightRefusal passwordPolicy(MaintenanceRequest request) {
    if (!MaintenanceResults.passwordReactivation(request)) throw new IllegalArgumentException();
    return new MaintenancePreflightRefusal(400);
  }
  static MaintenancePreflightRefusal current(int status) {
    if (status != 403 && status != 409) throw new IllegalArgumentException();
    return new MaintenancePreflightRefusal(status);
  }
}
