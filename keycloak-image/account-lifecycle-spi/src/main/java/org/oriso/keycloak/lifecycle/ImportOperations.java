package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;
import java.util.function.Supplier;
import org.keycloak.models.KeycloakSession;

/** Only an explicit captured IMPORT tuple may reach its finite read/complete-role-union operations. */
final class ImportOperations {
  static JsonNode read(KeycloakSession session,LifecycleAuthorization crypto,Map<String,Set<String>> mappings,
      Supplier<GeneralPolicy> policies,MaintenanceRequest request,String human){
    require(request,human);
    return ProtectedAccountOperations.protectedTarget(session,request)
        ? ProtectedAccountOperations.readCurrentOperation(session,crypto,request,human)
        : OrdinaryAccountOperations.read(session,crypto,mappings,policies.get(),request,human);
  }
  static void mutate(KeycloakSession session,LifecycleAuthorization crypto,Map<String,Set<String>> mappings,
      Supplier<GeneralPolicy> policies,MaintenanceRequest request,JsonNode body,String human){
    require(request,human);
    if(!"ordinary-profile".equals(request.command())||ProtectedAccountOperations.protectedTarget(session,request))deny();
    OrdinaryAccountOperations.mutate(session,crypto,mappings,policies.get(),request,body,human);
  }
  private static void require(MaintenanceRequest request,String human){
    if(request.workflow()==null||!"IMPORT".equals(request.workflow().path("kind").asText()))deny();
    if("IMPORT".equals(request.target().path("origin").path("kind").asText())&&human!=null)deny();
  }
  private ImportOperations(){}
}
