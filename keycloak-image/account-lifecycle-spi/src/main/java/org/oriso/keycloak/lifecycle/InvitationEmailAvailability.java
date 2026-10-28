package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Locale;
import java.util.Set;

/** One invitation recipient preflight. It never identifies or excludes an existing account. */
record InvitationEmailAvailability(String email, String family, String profileId, long profileVersion,
    String kind, String tenantId, String tenantMode, JsonNode origin) {
  static InvitationEmailAvailability parse(JsonNode body) {
    fields(body, "email", "profile", "tenantId", "tenantMode", "origin");
    String email = text(body, "email", 320, false);
    if (!email.equals(email.trim().toLowerCase(Locale.ROOT)) || !email.matches("[^\\s@]+@[^\\s@]+")) bad();
    var profile = body.path("profile");
    fields(profile, "family", "id", "version", "kind");
    String family = text(profile, "family", 20, false), kind = text(profile, "kind", 40, false);
    if (!("ORDINARY".equals(family) && Set.of("CONSULTANT", "AGENCY_ADMIN", "CONSULTANT_AGENCY_ADMIN").contains(kind))
        && !("PROTECTED".equals(family) && Set.of("TENANT_ADMIN", "PLATFORM_ADMIN").contains(kind))) bad();
    String id = text(profile, "id", "ORDINARY".equals(family) ? 100 : 255, false);
    long version = number(profile, "version", true);
    String tenant = text(body, "tenantId", 19, true), mode = text(body, "tenantMode", 20, false);
    if (!Set.of("EXISTING", "RESERVED_NEW", "UNASSIGNED").contains(mode)) bad();
    if (tenant != null) {
      if (!tenant.matches("0|[1-9][0-9]{0,18}")) bad();
      try { Long.parseLong(tenant); } catch (NumberFormatException malformed) { bad(); }
    }
    if ("EXISTING".equals(mode) && tenant == null
        || "UNASSIGNED".equals(mode) && (tenant != null || !"ORDINARY".equals(family) || !"CONSULTANT".equals(kind))
        || "PLATFORM_ADMIN".equals(kind) && (!"0".equals(tenant) || !"EXISTING".equals(mode))
        || !"PLATFORM_ADMIN".equals(kind) && "0".equals(tenant)) bad();
    var origin = body.path("origin");
    fields(origin, "kind", "workflowId", "humanSubject", "humanIssuer", "humanClient", "humanAuthority");
    if (!"HUMAN_ADMIN".equals(text(origin, "kind", 30, false))) deny();
    text(origin, "workflowId", 512, false);
    uuid(text(origin, "humanSubject", 36, false));
    text(origin, "humanIssuer", 512, false);
    text(origin, "humanClient", 255, false);
    if (!Set.of("PROTECTED_ACCOUNT_OPERATIONS_V1", "ORDINARY_ACCOUNT_OPERATIONS_V1")
        .contains(text(origin, "humanAuthority", 255, false))) deny();
    return new InvitationEmailAvailability(email, family, id, version, kind, tenant, mode, origin.deepCopy());
  }

  void requireTenant(HumanAdminSource source) {
    if (!"PLATFORM".equals(source.authority()) && !"EXISTING".equals(tenantMode)) deny();
    source.targetTenant(tenantId == null ? JSON.getNodeFactory().nullNode() : JSON.valueToTree(tenantId));
  }

  @Override public String toString() { return "InvitationEmailAvailability[redacted]"; }
}
