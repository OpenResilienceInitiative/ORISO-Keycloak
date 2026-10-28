package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;
import java.util.function.Supplier;
import org.keycloak.models.KeycloakSession;

/** Receiver-owned historical reach, separate from the unchanged result receipt and fresh authority. */
final class MaintenanceReplayReach {
  private static final Set<String> OPERATIONS=Set.of("account.read","account.profile","account.email",
      "account.delete","account.ordinary-profile","account.profile-transition","account.deactivate","account.reactivate","account.reassign-tenant");
  static final class Checked {
    private final JsonNode entries;
    private Checked(JsonNode entries){this.entries=entries.deepCopy();}
  }
  static Set<String> operations(MaintenanceRequest request){
    var result=new TreeSet<String>();result.add("account."+request.command());
    if("ordinary-profile".equals(request.command())&&request.change()!=null&&request.change().has("profile"))result.add("account.profile");
    if(!OPERATIONS.containsAll(result))deny();return Set.copyOf(result);
  }
  static Checked ordinary(MaintenanceRequest request,GeneralPolicy.Profile current,GeneralPolicy.Profile desired,Set<String> operations){
    return checked(request,"ORDINARY",current.id,current.version,desired.id,desired.version,operations);
  }
  static Checked protectedProfiles(MaintenanceRequest request,ProtectedInvitationConfiguration.Profile current,
      ProtectedInvitationConfiguration.Profile desired,Set<String> operations){
    return checked(request,"PROTECTED",current.id(),current.version(),desired.id(),desired.version(),operations);
  }
  static Checked transfer(MaintenanceRequest request,ProtectedInvitationConfiguration.Profile current,
      GeneralPolicy.Profile desired,Set<String> operations){
    if(!"HUMAN_ADMIN".equals(request.target().path("origin").path("kind").asText())
        ||!operations.equals(Set.of("account.profile-transition")))deny();
    var entries=JSON.createArrayNode();
    entries.add(entry("PROTECTED",current.id(),current.version(),request.target().path("tenantId"),operations));
    entries.add(entry("ORDINARY",desired.id,desired.version,request.target().path("tenantId"),operations));
    return new Checked(entries);
  }
  private static Checked checked(MaintenanceRequest request,String family,String id,long version,String desired,long desiredVersion,Set<String> operations){
    if(!"HUMAN_ADMIN".equals(request.target().path("origin").path("kind").asText()))return null;
    if(!OPERATIONS.containsAll(operations)||operations.isEmpty())deny();
    var entries=JSON.createArrayNode();entries.add(entry(family,id,version,request.target().path("tenantId"),operations));
    var tenant="reassign-tenant".equals(request.command())?request.change().path("tenantId"):request.target().path("tenantId");
    var next=entry(family,desired,desiredVersion,tenant,operations);if(!entries.path(0).equals(next))entries.add(next);
    return new Checked(entries);
  }
  private static JsonNode entry(String family,String id,long version,JsonNode tenant,Set<String> operations){
    var value=JSON.createObjectNode();value.put("family",family);value.put("profileId",id);value.put("profileVersion",version);
    value.set("tenantId",tenant.deepCopy());value.set("operations",JSON.valueToTree(new TreeSet<>(operations)));return value;
  }
  static String seal(LifecycleAuthorization crypto,AccountMaintenanceOperation row,MaintenanceRequest request,Checked checked){
    if(checked==null)throw new IllegalStateException("Authenticated human outcome lacks checked native reach");
    var value=JSON.createObjectNode();value.put("v",1);value.set("reach",checked.entries.deepCopy());
    value.put("mac",crypto.mac("maintenance-replay-reach/v1",payload(crypto,row,request,checked.entries)));
    return canonical(value);
  }
  private static JsonNode payload(LifecycleAuthorization crypto,AccountMaintenanceOperation row,MaintenanceRequest request,JsonNode reach){
    var value=JSON.createObjectNode();value.put("v",1);value.put("realmId",row.realmId);value.put("operationId",row.operationId);
    value.put("accountId",row.accountId);value.put("ownerClient",row.ownerClient);value.put("ownerSubject",row.ownerSubject);
    value.put("command",row.command);value.put("intentDigest",row.intentDigest);value.put("expectedState",row.expectedState);
    value.put("originDigest",crypto.mac("maintenance-origin",request.target().path("origin")));value.set("reach",reach.deepCopy());return value;
  }
  static JsonNode envelope(LifecycleAuthorization crypto,AccountMaintenanceOperation row,MaintenanceRequest request){
    if(row.replayReachJson==null)deny();
    try{
      var value=parse(row.replayReachJson);fields(value,"v","reach","mac");
      if(number(value,"v",true)!=1||!canonical(value).equals(row.replayReachJson))deny();
      String signature=text(value,"mac",64,false);hex(signature);var entries=value.path("reach");
      if(!entries.isArray()||entries.isEmpty()||entries.size()>2)deny();var unique=new HashSet<String>();
      for(var item:entries){
        fields(item,"family","profileId","profileVersion","tenantId","operations");
        if(!Set.of("ORDINARY","PROTECTED").contains(text(item,"family",20,false)))deny();
        text(item,"profileId",255,false);number(item,"profileVersion",true);
        String tenant=text(item,"tenantId",20,true);
        if(tenant!=null){if(!tenant.matches("0|[1-9][0-9]{0,18}"))deny();try{Long.parseLong(tenant);}catch(NumberFormatException malformed){deny();}}
        var operations=HumanPolicyJson.strings(item.path("operations"),1,OPERATIONS.size(),80);
        if(!OPERATIONS.containsAll(operations)||!operations.equals(operations(request))||!unique.add(canonical(item)))deny();
      }
      if(!LifecycleAuthorization.equal(signature,crypto.mac("maintenance-replay-reach/v1",payload(crypto,row,request,entries))))deny();
      return entries;
    }catch(jakarta.ws.rs.BadRequestException malformed){deny();return null;}
  }
  static void require(KeycloakSession session,LifecycleAuthorization crypto,Map<String,Set<String>> mappings,
      Supplier<GeneralPolicy> policies,GeneralPolicy configured,MaintenanceRequest request,AccountMaintenanceOperation prior,String human){
    var entries=envelope(crypto,prior,request);
    var source=HumanAdminSource.require(session,crypto,request,human);
    boolean refused="NO_EFFECT".equals(parse(prior.resultJson).path("result").asText());
    if(request.workflow()!=null&&"INACTIVITY".equals(request.workflow().path("kind").asText())&&!"PLATFORM".equals(source.authority()))deny();
    if(deleted(session,crypto,policies,mappings,source,request,prior))return;
    if(!refused)for(var entry:entries)requireOriginal(session,source,policies,request,entry);
    var needed=refused?Set.of("account.read"):operations(request);
    var nativeState=AccountLifecycleResource.lockedSnapshot(CurrentNativeHumanIdentity.entityManager(session),request.accountId());
    var tenants=nativeState.path("attributes").path("tenantId");
    JsonNode tenant=tenants.isMissingNode()||tenants.isEmpty()?JSON.nullNode():tenants.path(0);
    if(!tenants.isMissingNode()&&tenants.size()!=1)deny();
    var target=request.target().deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)target).set("tenantId",tenant.deepCopy());
    var current=new MaintenanceRequest("read",request.accountId(),target,null,null,null,null,null,request.workflow());
    if(!OrdinaryAccountOperations.adoptedTarget(session,configured,current) && ProtectedAccountOperations.protectedTarget(session,current))
      ProtectedAccountOperations.replayReach(session,crypto,current,human,needed);
    else OrdinaryAccountOperations.replayReach(session,crypto,mappings,policies.get(),current,human,needed);
  }
  static void requireOriginal(KeycloakSession session,HumanAdminSource source,Supplier<GeneralPolicy> policies,
      MaintenanceRequest request,JsonNode entry){
    source.targetTenant(entry.path("tenantId"));String id=entry.path("profileId").asText();long version=entry.path("profileVersion").longValue();
    var operations=HumanPolicyJson.strings(entry.path("operations"),1,OPERATIONS.size(),80);
    var target=request.target().deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)target).set("tenantId",entry.path("tenantId").deepCopy());
    var selected=new MaintenanceRequest("read",request.accountId(),target,null,null,null,null,null,request.workflow());
    if("ORDINARY".equals(entry.path("family").asText())){
      var policy=policies.get();var profile=policy.profile(id,version);policy.validateProfile(session,profile);
      for(String operation:operations)policy.requireAdmin(source,selected,operation,profile,profile);
    }else{
      var config=ProtectedInvitationFactory.checkedBootstrapConfiguration(session);var profile=config.profiles.get(id);
      if(profile==null||profile.version()!=version)deny();config.validateProfile(session,profile);
      for(String operation:operations)source.protectedOperation(request.accountId(),id,operation);
    }
  }
  private static boolean deleted(KeycloakSession session,LifecycleAuthorization crypto,Supplier<GeneralPolicy> policies,
      Map<String,Set<String>> mappings,HumanAdminSource source,MaintenanceRequest request,AccountMaintenanceOperation prior){
    var em=CurrentNativeHumanIdentity.entityManager(session);String realm=session.getContext().getRealm().getId();
    var rows=em.createQuery("select o from AccountMaintenanceOperation o where o.realmId=:realm and o.accountId=:account and o.command='delete'",AccountMaintenanceOperation.class)
        .setParameter("realm",realm).setParameter("account",request.accountId()).setLockMode(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE).setMaxResults(2).getResultList();
    if(rows.isEmpty())return false;if(rows.size()!=1)deny();var row=rows.get(0);em.refresh(row);
    var result=parse(row.resultJson);fields(result,"operationId","accountId","result","receipt");
    String saved=text(result,"receipt",16000,false);String[] pieces=saved.split("\\.",-1);if(pieces.length!=2)deny();
    JsonNode receipt;try{receipt=parse(Base64.getUrlDecoder().decode(pieces[0]));}catch(IllegalArgumentException malformed){deny();return false;}
    fields(receipt,"realmId","accountId","operationId","command","ownerClient","ownerSubject","intentDigest","previousState","tenantId","originDigest","result");
    if(!realm.equals(row.realmId)||!request.accountId().equals(row.accountId)||!"delete".equals(row.command)
        ||!prior.ownerClient.equals(row.ownerClient)||!prior.ownerSubject.equals(row.ownerSubject)
        ||!realm.equals(receipt.path("realmId").asText())||!row.accountId.equals(receipt.path("accountId").asText())
        ||!row.operationId.equals(receipt.path("operationId").asText())||!"delete".equals(receipt.path("command").asText())
        ||!row.ownerClient.equals(receipt.path("ownerClient").asText())||!row.ownerSubject.equals(receipt.path("ownerSubject").asText())
        ||!row.intentDigest.equals(receipt.path("intentDigest").asText())||!row.expectedState.equals(receipt.path("previousState").asText())
        ||!"DELETED".equals(receipt.path("result").asText())||!row.operationId.equals(result.path("operationId").asText())
        ||!row.accountId.equals(result.path("accountId").asText())||!"DELETED".equals(result.path("result").asText())
        ||!LifecycleAuthorization.equal(crypto.receipt("maintenance-operation-receipt",receipt),saved))deny();
    var policy=policies.get();var historical=OrdinaryAccountOperations.deletedProfile(session,crypto,mappings,policy,request.accountId());
    if(!historical.tenant().equals(receipt.path("tenantId")))deny();
    var target=request.target().deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)target).set("tenantId",historical.tenant().deepCopy());
    var selected=new MaintenanceRequest("read",request.accountId(),target,null,null,null,null,null,request.workflow());
    policy.requireAdmin(source,selected,"account.read",historical.profile(),historical.profile());
    return true;
  }
  private MaintenanceReplayReach(){}
}
