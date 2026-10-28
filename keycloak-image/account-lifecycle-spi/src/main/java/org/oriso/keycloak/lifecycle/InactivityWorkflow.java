package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Set;

/** Original claimed SQL assertions only; independently checked native grants select effects. */
final class InactivityWorkflow {
  static JsonNode parse(String command,JsonNode target,JsonNode workflow){
    fields(workflow,"v","kind","workId","action","rowDigest","revision","assignedMonths","lastActivity","dueAt","suspensionOperationId");
    if(number(workflow,"v",true)!=1||!"INACTIVITY".equals(text(workflow,"kind",20,false)))bad();
    String work=uuid(text(workflow,"workId",36,false));String action=text(workflow,"action",10,false);
    if(!Set.of("SUSPEND","RESTORE").contains(action)||!Set.of("read","SUSPEND".equals(action)?"deactivate":"reactivate").contains(command))bad();
    hex(text(workflow,"rowDigest",64,false));number(workflow,"revision",false);
    if(number(workflow,"assignedMonths",true)>Integer.MAX_VALUE)bad();
    long last=number(workflow,"lastActivity",true),due=number(workflow,"dueAt",true);if(due<last)bad();
    String suspended=text(workflow,"suspensionOperationId",36,true);
    if("SUSPEND".equals(action)?suspended!=null:suspended==null)bad();if(suspended!=null)uuid(suspended);
    var origin=target.path("origin");
    if(!work.equals(origin.path("workflowId").asText())||!Set.of("INACTIVITY","HUMAN_ADMIN").contains(origin.path("kind").asText()))deny();
    if("HUMAN_ADMIN".equals(origin.path("kind").asText())&&!"PROTECTED_ACCOUNT_OPERATIONS_V1".equals(origin.path("humanAuthority").asText()))deny();
    return workflow.deepCopy();
  }
  static void requireFreshSuspend(MaintenanceRequest request){
    if("INACTIVITY".equals(request.target().path("origin").path("kind").asText())
        &&"SUSPEND".equals(request.workflow().path("action").asText())
        &&request.workflow().path("dueAt").longValue()>java.time.Instant.now().getEpochSecond())deny();
  }
  private InactivityWorkflow(){}
}
