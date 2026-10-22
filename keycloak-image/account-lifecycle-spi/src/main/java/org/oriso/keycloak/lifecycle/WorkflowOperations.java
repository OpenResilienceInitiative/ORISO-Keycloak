package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;

/** Explicit installed automation grants. Separate from every human operation grant. */
final class WorkflowOperations {
  private record Grant(String kind,Set<String> profiles, Set<String> operations) {}
  private final List<Grant> grants;
  WorkflowOperations(JsonNode config, Set<String> profileIds) {this(config,profileIds,false);}
  WorkflowOperations(JsonNode config, Set<String> profileIds,boolean protectedProfiles) {
    if (!config.has("workflowOperations")) { grants=List.of(); return; }
    var supplied=config.path("workflowOperations");
    if(!supplied.isArray() || supplied.size()>20)bad();
    var result=new ArrayList<Grant>();var unique=new HashSet<Grant>();
    for(var value:supplied){
      fields(value,"kind","targetProfiles","operations");
      String kind=text(value,"kind",20,false);if(!Set.of("INACTIVITY","IMPORT").contains(kind))bad();
      var profiles=strings(value.path("targetProfiles"),100,255);
      var operations=strings(value.path("operations"),3,80);
      var allowed="INACTIVITY".equals(kind)?Set.of("account.read","account.deactivate","account.reactivate")
          :protectedProfiles?Set.of("account.read"):Set.of("account.read","account.ordinary-profile");
      if(!profileIds.containsAll(profiles)||!allowed.containsAll(operations))bad();
      var grant=new Grant(kind,profiles,operations);if(!unique.add(grant))bad();result.add(grant);
    }
    grants=List.copyOf(result);
  }
  void require(String profile,String operation){require("INACTIVITY",profile,operation);}
  void require(String kind,String profile,String operation){
    if(grants.stream().noneMatch(g->g.kind.equals(kind)&&g.profiles.contains(profile)&&g.operations.contains(operation)))deny();
  }
  private static Set<String> strings(JsonNode array,int max,int length){
    if(!array.isArray()||array.isEmpty()||array.size()>max)bad();var result=new HashSet<String>();
    for(var item:array){if(!item.isTextual()||item.asText().isBlank()||item.asText().length()>length
        ||item.asText().chars().anyMatch(c->c<32||c==127)||!result.add(item.asText()))bad();}return Set.copyOf(result);
  }
}
