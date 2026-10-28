package org.oriso.keycloak.lifecycle;

import static org.junit.Assert.*;
import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Test;

public class MaintenanceRoleChangeTest {
  private JsonNode profile(String family,String... roles){
    var value=JSON.createObjectNode();value.put("kind",family);
    value.set("realmRoles",JSON.valueToTree(new java.util.TreeSet<>(java.util.List.of(roles))));
    value.putObject("clientRoles");return value;
  }
  private JsonNode removal(){return parse("{\"kind\":\"REMOVE_ADMINISTRATOR_IDENTITY\"}");}
  @Test public void removalPreservesExactConsultantSubsetForBothFamilies(){
    var consultant=profile("CONSULTANT","consultant","group-chat-consultant");
    MaintenanceRoleChange.require(removal(),"ORDINARY",profile("CONSULTANT_AGENCY_ADMIN","consultant","group-chat-consultant","restricted-agency-admin","user-admin"),consultant);
    MaintenanceRoleChange.require(removal(),"PROTECTED",profile("TENANT_ADMIN","consultant","group-chat-consultant","tenant-admin"),consultant);
    MaintenanceRoleChange.require(removal(),"PROTECTED",profile("PLATFORM_ADMIN","agency-admin","consultant","tenant-admin"),profile("CONSULTANT","consultant"));
  }
  @Test public void removalCannotAddChatDropConsultantRetainAdminOrChangeClientRoles(){
    var source=profile("TENANT_ADMIN","consultant","tenant-admin");
    for(var desired:java.util.List.of(profile("CONSULTANT","consultant","group-chat-consultant"),profile("TENANT_ADMIN","tenant-admin"),profile("TENANT_ADMIN","consultant","tenant-admin")))
      assertThrows(jakarta.ws.rs.ForbiddenException.class,()->MaintenanceRoleChange.require(removal(),"PROTECTED",source,desired));
    var client=profile("CONSULTANT","consultant");((com.fasterxml.jackson.databind.node.ObjectNode)client.path("clientRoles")).putArray("app").add("new");
    assertThrows(jakarta.ws.rs.ForbiddenException.class,()->MaintenanceRoleChange.require(removal(),"PROTECTED",source,client));
    assertThrows(jakarta.ws.rs.ForbiddenException.class,()->MaintenanceRoleChange.require(removal(),"ORDINARY",profile("CONSULTANT","consultant"),profile("CONSULTANT","consultant")));
  }
}
