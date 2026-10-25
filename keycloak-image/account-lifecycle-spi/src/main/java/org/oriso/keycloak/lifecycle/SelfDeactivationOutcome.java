package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Set;
import org.keycloak.models.KeycloakSession;

/** One fixed SELF disable and its historical result. A lookup can never dispatch a command. */
final class SelfDeactivationOutcome {
  private static final String KIND="SELF_DEACTIVATION_OUTCOME_V1";
  private static final String DOMAIN="maintenance-self-deactivation-outcome/v1";

  static final class Prepared {
    private final JsonNode original;
    private final long birth,deadline;
    private final String provenance;
    private final GeneralPolicy.Profile profile;
    private Prepared(JsonNode original,long birth,long deadline,String provenance,GeneralPolicy.Profile profile){
      this.original=original.deepCopy();this.birth=birth;this.deadline=deadline;this.provenance=provenance;this.profile=profile;
    }
  }

  static Prepared deactivate(KeycloakSession session,LifecycleAuthorization crypto,
      java.util.Map<String,Set<String>> mappings,GeneralPolicy policy,MaintenanceRequest request,String rawHuman){
    fixed(request);
    if(policy==null||rawHuman==null||!rawHuman.startsWith("Bearer "))deny();
    var source=OrdinaryAccountOperations.selfDeactivationSource(session,crypto,mappings,policy,request,rawHuman);
    var human=CurrentNativeHumanIdentity.require(session,policy.nativePolicy,rawHuman.substring(7));
    if(!request.accountId().equals(human.subject())||!"ASKER".equals(LifecycleGroups.allowedKind(source.profile().realmRoles))
        ||!source.nativeState().path("enabled").asBoolean())deny();
    if(!LifecycleAuthorization.equal(request.expectedState(),source.state()))throw MaintenancePreflightRefusal.current(409);
    long created=birth(session,request.accountId());
    var prepared=new Prepared(source.nativeState(),created,human.validatedJwtExpiresAt(),source.lineage().provenance(),source.profile());
    var user=session.users().getUserById(session.getContext().getRealm(),request.accountId());
    if(user==null)deny();user.setEnabled(false);
    CurrentNativeHumanIdentity.entityManager(session).flush();
    var expected=prepared.original.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)expected).put("enabled",false);
    if(!canonical(expected).equals(canonical(AccountLifecycleResource.lockedSnapshot(CurrentNativeHumanIdentity.entityManager(session),request.accountId())))
        ||prepared.birth!=birth(session,request.accountId()))throw new IllegalStateException("Native SELF deactivation did not complete");
    return prepared;
  }

  static String seal(LifecycleAuthorization crypto,AccountMaintenanceOperation row,MaintenanceRequest request,Prepared prepared){
    if(prepared==null)throw new IllegalStateException("Missing original SELF deactivation source");
    var profile=JSON.createObjectNode();profile.put("id",prepared.profile.id);profile.put("version",prepared.profile.version);
    profile.set("tenantId",request.target().path("tenantId").deepCopy());profile.set("nativeProfile",prepared.profile.snapshot.deepCopy());
    profile.put("humanValidUntil",prepared.deadline);
    var binding=tuple(crypto,row,request);binding.put("createdTimestamp",prepared.birth);
    binding.put("provenanceDigest",prepared.provenance);binding.set("profile",profile);
    var envelope=JSON.createObjectNode();envelope.put("v",1);envelope.put("kind",KIND);envelope.set("binding",binding);
    envelope.put("mac",crypto.mac(DOMAIN,binding));return canonical(envelope);
  }

  /** Constructor-private verified original data; only the exact saved-only operation creates it. */
  static final class Checked {
    private final JsonNode binding;
    private Checked(JsonNode binding){this.binding=binding.deepCopy();}
    void requireProfile(GeneralPolicy policy,GeneralPolicy.Profile profile,MaintenanceLineage.Current lineage,MaintenanceRequest request){
      var original=binding.path("profile");
      if(!"ASKER".equals(LifecycleGroups.allowedKind(profile.realmRoles))
          ||!original.path("id").asText().equals(profile.id)||original.path("version").longValue()!=profile.version
          ||!canonical(original.path("nativeProfile")).equals(canonical(profile.snapshot))
          ||!original.path("tenantId").equals(request.target().path("tenantId"))
          ||!lineage.tenant().equals(original.path("tenantId"))
          ||!binding.path("provenanceDigest").asText().equals(lineage.provenance())
          ||!profile.selfOperations.containsAll(Set.of("account.read","account.deactivate"))
          ||!policy.nativePolicy.issuer.equals(request.target().path("origin").path("humanIssuer").asText())
          ||!policy.nativePolicy.clients.contains(request.target().path("origin").path("humanClient").asText()))deny();
    }
    void requirePostState(KeycloakSession session,LifecycleAuthorization crypto,MaintenanceRequest request,JsonNode state){
      var current=state.path("account");
      if(current.path("enabled").asBoolean()||binding.path("createdTimestamp").longValue()!=birth(session,request.accountId()))deny();
      var original=state.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)original.path("account")).put("enabled",true);
      if(!LifecycleAuthorization.equal(request.expectedState(),crypto.mac("maintenance-state",original)))deny();
    }
  }

  static void requireSaved(KeycloakSession session,LifecycleAuthorization crypto,java.util.Map<String,Set<String>> mappings,
      GeneralPolicy policy,MaintenanceRequest request,AccountMaintenanceOperation row){
    fixed(request);
    if(row.replayReachJson==null||!"backend-account-admin".equals(row.ownerClient)||!crypto.adminSubject.equals(row.ownerSubject))deny();
    var value=parse(row.replayReachJson);fields(value,"v","kind","binding","mac");
    if(number(value,"v",true)!=1||!KIND.equals(text(value,"kind",64,false))||!canonical(value).equals(row.replayReachJson))deny();
    var binding=value.path("binding");fields(binding,"realmId","accountId","operationId","command","ownerClient","ownerSubject",
        "intentDigest","expectedState","originDigest","createdTimestamp","provenanceDigest","profile");
    var expected=tuple(crypto,row,request);var actual=binding.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode)actual).remove(java.util.List.of("createdTimestamp","provenanceDigest","profile"));
    if(!expected.equals(actual)||!LifecycleAuthorization.equal(text(value,"mac",64,false),crypto.mac(DOMAIN,binding)))deny();
    number(binding,"createdTimestamp",true);hex(text(binding,"provenanceDigest",64,false));
    var profile=binding.path("profile");fields(profile,"id","version","tenantId","nativeProfile","humanValidUntil");
    text(profile,"id",100,false);number(profile,"version",true);number(profile,"humanValidUntil",true);
    if(!profile.path("tenantId").equals(request.target().path("tenantId"))||!profile.path("nativeProfile").isObject())deny();
    OrdinaryAccountOperations.savedSelfDeactivation(session,crypto,mappings,policy,request,new Checked(binding));
  }

  private static com.fasterxml.jackson.databind.node.ObjectNode tuple(LifecycleAuthorization crypto,AccountMaintenanceOperation row,MaintenanceRequest request){
    var value=JSON.createObjectNode();value.put("realmId",row.realmId);value.put("accountId",row.accountId);value.put("operationId",row.operationId);
    value.put("command",row.command);value.put("ownerClient",row.ownerClient);value.put("ownerSubject",row.ownerSubject);
    value.put("intentDigest",row.intentDigest);value.put("expectedState",row.expectedState);
    value.put("originDigest",crypto.mac("maintenance-origin",request.target().path("origin")));return value;
  }

  private static void fixed(MaintenanceRequest request){
    if(!"deactivate".equals(request.command())||request.workflow()!=null||request.change()==null||!request.change().isObject()||!request.change().isEmpty()
        ||!"SELF".equals(request.target().path("origin").path("kind").asText())
        ||!request.accountId().equals(request.target().path("origin").path("humanSubject").asText())
        ||!request.target().path("origin").path("humanAuthority").isNull())deny();
  }

  private static long birth(KeycloakSession session,String account){
    var rows=CurrentNativeHumanIdentity.entityManager(session).createNativeQuery(
        "select CREATED_TIMESTAMP from USER_ENTITY where ID=:account and REALM_ID=:realm for update")
        .setParameter("account",account).setParameter("realm",session.getContext().getRealm().getId()).getResultList();
    if(rows.size()!=1||!(rows.get(0) instanceof Number number)||number.longValue()<=0)deny();
    return ((Number)rows.get(0)).longValue();
  }
  private SelfDeactivationOutcome(){}
}
