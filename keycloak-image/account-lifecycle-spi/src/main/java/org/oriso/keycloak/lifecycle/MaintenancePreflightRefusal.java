package org.oriso.keycloak.lifecycle;

/** Authenticated finite intent, definitely rejected before its first native write. */
final class MaintenancePreflightRefusal extends jakarta.ws.rs.WebApplicationException {
  private MaintenancePreflightRefusal(int status) { super(status); }
  static MaintenancePreflightRefusal current(int status) {
    if (status != 403 && status != 409) throw new IllegalArgumentException();
    return new MaintenancePreflightRefusal(status);
  }
}
