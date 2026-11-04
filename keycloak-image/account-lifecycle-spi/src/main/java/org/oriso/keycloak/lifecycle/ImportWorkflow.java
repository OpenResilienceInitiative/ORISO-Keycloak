package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Set;

/** Opaque owning-row assertions only. This parser never confers native mutation authority. */
final class ImportWorkflow {
  static final Set<String> ROLES=Set.of("consultant","group-chat-consultant","restricted-agency-admin","user-admin");
  static JsonNode parse(String command,JsonNode target,JsonNode workflow){
    fields(workflow,"v","kind","workId","sourceDigest","recordNumber","rowDigest","requiredRoles");
    if(number(workflow,"v",true)!=1||!"IMPORT".equals(text(workflow,"kind",20,false))
        ||!Set.of("read","ordinary-profile").contains(command))bad();
    String work=uuid(text(workflow,"workId",36,false));
    hex(text(workflow,"sourceDigest",64,false));number(workflow,"recordNumber",true);hex(text(workflow,"rowDigest",64,false));
    var roles=workflow.path("requiredRoles");if(!roles.isArray()||roles.isEmpty()||roles.size()>4)bad();
    String previous=null;boolean consultant=false;
    for(var role:roles){
      if(!role.isTextual()||!ROLES.contains(role.asText())||previous!=null&&previous.compareTo(role.asText())>=0)bad();
      previous=role.asText();if("consultant".equals(previous))consultant=true;
    }
    if(!consultant)bad();var origin=target.path("origin");
    if(!work.equals(origin.path("workflowId").asText())||!Set.of("IMPORT","HUMAN_ADMIN").contains(origin.path("kind").asText()))deny();
    if("HUMAN_ADMIN".equals(origin.path("kind").asText())&&!"PROTECTED_ACCOUNT_OPERATIONS_V1".equals(origin.path("humanAuthority").asText()))deny();
    return workflow.deepCopy();
  }
  private ImportWorkflow(){}
}
