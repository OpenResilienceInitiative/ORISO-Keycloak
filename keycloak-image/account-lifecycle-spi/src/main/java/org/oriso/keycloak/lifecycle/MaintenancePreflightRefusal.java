package org.oriso.keycloak.lifecycle;

/** Authenticated finite intent, definitely rejected before its first native write. */
final class MaintenancePreflightRefusal extends jakarta.ws.rs.WebApplicationException {
  private final MaintenanceReplayReach.Checked reach;
  private MaintenancePreflightRefusal(int status) { this(status,null); }
  private MaintenancePreflightRefusal(int status,MaintenanceReplayReach.Checked reach) { super(status);this.reach=reach; }
  MaintenanceReplayReach.Checked reach(){return reach;}
  MaintenancePreflightRefusal withReach(MaintenanceReplayReach.Checked checked){
    return reach==null?new MaintenancePreflightRefusal(getResponse().getStatus(),checked):this;
  }
  static MaintenancePreflightRefusal passwordPolicy(MaintenanceRequest request) {
    return passwordPolicy(request,null);
  }
  static MaintenancePreflightRefusal passwordPolicy(MaintenanceRequest request,MaintenanceReplayReach.Checked reach) {
    if (!MaintenanceResults.passwordReactivation(request) && !"self-password".equals(request.command())) throw new IllegalArgumentException();
    return new MaintenancePreflightRefusal(400,reach);
  }
  static MaintenancePreflightRefusal current(int status) {
    return current(status,null);
  }
  static MaintenancePreflightRefusal current(int status,MaintenanceReplayReach.Checked reach) {
    if (status != 403 && status != 409) throw new IllegalArgumentException();
    return new MaintenancePreflightRefusal(status,reach);
  }
}
