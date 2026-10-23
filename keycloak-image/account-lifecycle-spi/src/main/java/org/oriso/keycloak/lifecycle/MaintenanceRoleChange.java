package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;

/** Closed source-supported role additions, rechecked when following the immutable native lineage. */
final class MaintenanceRoleChange {
  static JsonNode capsule(MaintenanceRequest request){
    var value=JSON.createObjectNode();
    if("profile-transition".equals(request.command()))value.put("kind",request.change().path("transition").asText());
    else if("ordinary-profile".equals(request.command())&&request.workflow()!=null&&"IMPORT".equals(request.workflow().path("kind").asText())){
      value.put("kind","IMPORT");value.set("requiredRoles",request.workflow().path("requiredRoles").deepCopy());
    }else return null;
    return value;
  }
  static void requireImportProfile(JsonNode profile){
    if(!Set.of("CONSULTANT","CONSULTANT_AGENCY_ADMIN").contains(LifecycleGroups.allowedKind(roles(profile))))deny();
  }
  static void require(JsonNode capsule,String family,JsonNode from,JsonNode desired){
    String kind=text(capsule,"kind",40,false);
    if(!canonical(from.path("clientRoles")).equals(canonical(desired.path("clientRoles"))))deny();
    var current=roles(from);var next=roles(desired);var union=new TreeSet<>(current);
    if(!next.containsAll(current))deny();
    if("PROTECTED".equals(family)&&(!from.path("kind").equals(desired.path("kind"))
        ||!Set.of("TENANT_ADMIN","PLATFORM_ADMIN").contains(from.path("kind").asText())))deny();
    if("IMPORT".equals(kind)){
      fields(capsule,"kind","requiredRoles");if(!"ORDINARY".equals(family))deny();
      requireImportProfile(from);requireImportProfile(desired);
      var required=HumanPolicyJson.strings(capsule.path("requiredRoles"),1,4,255);
      if(!required.contains("consultant")||!ImportWorkflow.ROLES.containsAll(required))deny();
      union.addAll(required);if(!next.equals(union))deny();return;
    }
    fields(capsule,"kind");
    if("ADD_CONSULTANT_IDENTITY".equals(kind)){
      if("ORDINARY".equals(family)&&!Set.of("AGENCY_ADMIN","CONSULTANT_AGENCY_ADMIN").contains(LifecycleGroups.allowedKind(current)))deny();
      union.add("consultant");var withChat=new TreeSet<>(union);withChat.add("group-chat-consultant");
      if(!next.equals(union)&&!next.equals(withChat))deny();
    }else if("ADD_AGENCY_ADMIN_IDENTITY".equals(kind)){
      if(!current.contains("consultant"))deny();
      if("ORDINARY".equals(family)&&!Set.of("CONSULTANT","CONSULTANT_AGENCY_ADMIN").contains(LifecycleGroups.allowedKind(current)))deny();
      union.addAll(Set.of("restricted-agency-admin","user-admin"));if(!next.equals(union))deny();
    }else deny();
    if("ORDINARY".equals(family)&&!"CONSULTANT_AGENCY_ADMIN".equals(LifecycleGroups.allowedKind(next)))deny();
  }
  private static Set<String> roles(JsonNode profile){return HumanPolicyJson.strings(profile.path("realmRoles"),1,100,255);}
  private MaintenanceRoleChange(){}
}
