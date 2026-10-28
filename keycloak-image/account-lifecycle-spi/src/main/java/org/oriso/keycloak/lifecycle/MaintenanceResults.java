package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.KeycloakSession;

/** Original UPDATED11 and separately versioned, permanently fenced NO_EFFECT12. */
final class MaintenanceResults {
  static Response noEffect(KeycloakSession session, LifecycleAuthorization crypto,
      LifecycleAuthorization.CheckedMachine machine, MaintenanceRequest request, JsonNode body, int status) {
    return noEffect(session,crypto,machine,request,body,status,null);
  }
  static Response noEffect(KeycloakSession session,LifecycleAuthorization crypto,
      LifecycleAuthorization.CheckedMachine machine,MaintenanceRequest request,JsonNode body,int status,MaintenanceReplayReach.Checked reach) {
    if (!allowedStatus(request, status)) deny();
    String digest = crypto.mac("maintenance-intent", body);
    var payload = payload(session, crypto, machine, request, digest, "NO_EFFECT"); payload.put("status", status);
    var result = JSON.createObjectNode(); result.put("operationId", request.operationId());
    result.put("accountId", request.accountId()); result.put("result", "NO_EFFECT"); result.put("status", status);
    result.put("receipt", crypto.receipt("maintenance-no-effect-receipt/v1", payload));
    persist(session, machine, request, digest, result,reach,crypto);
    CurrentNativeHumanIdentity.entityManager(session).flush();
    return Response.status(status).entity(result).header("Cache-Control", "no-store").build();
  }
  static Response saved(AccountMaintenanceOperation prior, LifecycleAuthorization crypto,
      MaintenanceRequest request) {
    var result = parse(prior.resultJson);
    boolean refused = "NO_EFFECT".equals(result.path("result").asText());
    if (refused) fields(result, "operationId", "accountId", "result", "status", "receipt");
    else fields(result, "operationId", "accountId", "result", "receipt");
    if (!request.operationId().equals(result.path("operationId").asText())
        || !request.accountId().equals(result.path("accountId").asText())) deny();
    int status = refused ? (int) number(result, "status", true) : 200;
    if (refused && !allowedStatus(request, status) || !refused && !"UPDATED".equals(result.path("result").asText())) deny();
    var value = JSON.createObjectNode(); value.put("realmId", prior.realmId); value.put("accountId", prior.accountId);
    value.put("operationId", prior.operationId); value.put("command", prior.command); value.put("ownerClient", prior.ownerClient);
    value.put("ownerSubject", prior.ownerSubject); value.put("intentDigest", prior.intentDigest); value.put("previousState", prior.expectedState);
    value.set("tenantId", request.target().path("tenantId")); value.put("originDigest", crypto.mac("maintenance-origin", request.target().path("origin")));
    value.put("result", refused ? "NO_EFFECT" : "UPDATED"); if (refused) value.put("status", status);
    if (!LifecycleAuthorization.equal(crypto.receipt(refused ? "maintenance-no-effect-receipt/v1" : "maintenance-operation-receipt", value),
        text(result, "receipt", 16000, false))) deny();
    return Response.status(status).entity(result).header("Cache-Control", "no-store").build();
  }
  static com.fasterxml.jackson.databind.node.ObjectNode payload(KeycloakSession session, LifecycleAuthorization crypto,
      LifecycleAuthorization.CheckedMachine machine, MaintenanceRequest request, String digest, String result) {
    var value = JSON.createObjectNode(); value.put("realmId", session.getContext().getRealm().getId());
    value.put("accountId", request.accountId()); value.put("operationId", request.operationId()); value.put("command", request.command());
    value.put("ownerClient", machine.clientId()); value.put("ownerSubject", machine.subject()); value.put("intentDigest", digest);
    value.put("previousState", request.expectedState()); value.set("tenantId", request.target().path("tenantId"));
    value.put("originDigest", crypto.mac("maintenance-origin", request.target().path("origin"))); value.put("result", result);
    return value;
  }
  static void persist(KeycloakSession session, LifecycleAuthorization.CheckedMachine machine,
      MaintenanceRequest request, String digest, JsonNode result) {
    persist(session,machine,request,digest,result,null,null);
  }
  private static void persist(KeycloakSession session,LifecycleAuthorization.CheckedMachine machine,
      MaintenanceRequest request,String digest,JsonNode result,MaintenanceReplayReach.Checked reach,LifecycleAuthorization crypto) {
    var realm = session.getContext().getRealm().getId(); var saved = new AccountMaintenanceOperation();
    saved.id = realm + ":" + request.operationId(); saved.realmId = realm; saved.operationId = request.operationId();
    saved.accountId = request.accountId(); saved.command = request.command(); saved.ownerClient = machine.clientId();
    saved.ownerSubject = machine.subject(); saved.intentDigest = digest; saved.expectedState = request.expectedState();
    saved.resultJson = canonical(result);
    if("HUMAN_ADMIN".equals(request.target().path("origin").path("kind").asText()))
      saved.replayReachJson=MaintenanceReplayReach.seal(crypto,saved,request,reach);
    CurrentNativeHumanIdentity.entityManager(session).persist(saved);
  }
  static Response updated(KeycloakSession session, LifecycleAuthorization crypto,
      LifecycleAuthorization.CheckedMachine machine, MaintenanceRequest request, JsonNode body) {
    String digest = crypto.mac("maintenance-intent", body);
    var result = JSON.createObjectNode(); result.put("operationId", request.operationId());
    result.put("accountId", request.accountId()); result.put("result", "UPDATED");
    result.put("receipt", crypto.receipt("maintenance-operation-receipt", payload(session, crypto, machine, request, digest, "UPDATED")));
    persist(session, machine, request, digest, result);
    var realm=session.getContext().getRealm();
    if(realm.isAdminEventsEnabled()){
      var event=new org.keycloak.events.admin.AdminEvent();event.setTime(System.currentTimeMillis());event.setRealmId(realm.getId());
      event.setOperationType(org.keycloak.events.admin.OperationType.UPDATE);event.setResourceType(org.keycloak.events.admin.ResourceType.USER);
      event.setResourcePath("accounts/"+request.accountId());
      var details=new org.keycloak.events.admin.AuthDetails();details.setRealmId(realm.getId());
      details.setClientId(machine.clientId());details.setUserId(machine.subject());event.setAuthDetails(details);
      session.getProvider(org.keycloak.events.EventStoreProvider.class).onEvent(event,false);
    }
    CurrentNativeHumanIdentity.entityManager(session).flush();
    return Response.ok(result).header("Cache-Control", "no-store").build();
  }
  private static boolean allowedStatus(MaintenanceRequest request, int status) {
    return status == 403 || status == 409 || status == 400 && (java.util.Set.of("password-reset", "self-password").contains(request.command()) || passwordReactivation(request));
  }
  static boolean passwordReactivation(MaintenanceRequest request) {
    if (!"reactivate".equals(request.command()) || request.workflow() != null || request.change() == null
        || !request.change().isObject() || request.change().size() != 3) return false;
    for (String key : java.util.List.of("expectedUsername", "expectedEmail", "password"))
      if (!request.change().path(key).isTextual() || request.change().path(key).asText().isBlank()) return false;
    return true;
  }
  private MaintenanceResults() {}
}
