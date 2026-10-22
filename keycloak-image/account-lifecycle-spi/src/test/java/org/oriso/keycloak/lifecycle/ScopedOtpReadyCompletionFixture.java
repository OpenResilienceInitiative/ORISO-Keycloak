package org.oriso.keycloak.lifecycle;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.annotation.Priority;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.utils.KeycloakSessionUtil;

/** Isolated test JAR only: observe an exact native READY commit whose human session is revoked. */
@Provider
@Priority(20)
public final class ScopedOtpReadyCompletionFixture implements ContainerResponseFilter {
  private static void nullAdoptionTimestamp(ContainerRequestContext request, ContainerResponseContext response, String account) {
    if (!account.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        || !"GET".equals(request.getMethod()) || response.getStatus() != 200
        || !(response.getEntity() instanceof org.keycloak.representations.idm.UserRepresentation user)
        || !account.equals(user.getId()) || user.getUsername() == null || !user.getUsername().startsWith("adopted-null-"))
      throw new IllegalStateException("Invalid isolated null adoption fixture scope");
    var session=KeycloakSessionUtil.getKeycloakSession();
    if(session==null || session.getContext().getRealm()==null || !session.getTransactionManager().isActive())
      throw new IllegalStateException("Isolated adoption fixture requires native transaction");
    var realm=session.getContext().getRealm();
    if(!request.getUriInfo().getPath().replaceFirst("^/", "").equals("admin/realms/"+realm.getName()+"/users/"+account))
      throw new IllegalStateException("Isolated adoption fixture requires exact stock native user read");
    var config=LifecycleJson.parse(System.getenv("ORISO_ACCOUNT_MAINTENANCE_CONFIG"));boolean selected=false;
    for(var entry:config.path("adoptedAccounts")) if(account.equals(entry.path("accountId").asText())
        && "user-v1".equals(entry.path("ordinaryProfileId").asText()) && entry.path("profileVersion").asLong()==1) selected=true;
    if(!selected)throw new IllegalStateException("Exact synthetic adoption fixture is not configured");
    var em=session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var locked=em.createNativeQuery("select CREATED_TIMESTAMP from USER_ENTITY where ID=:id and REALM_ID=:realm for update")
        .setParameter("id",account).setParameter("realm",realm.getId()).getResultList();
    if(locked.size()!=1 || locked.get(0)==null)throw new IllegalStateException("Synthetic native incarnation missing");
    if(em.createNativeQuery("update USER_ENTITY set CREATED_TIMESTAMP=null where ID=:id and REALM_ID=:realm")
        .setParameter("id",account).setParameter("realm",realm.getId()).executeUpdate()!=1)
      throw new IllegalStateException("Synthetic native timestamp fixture did not complete");
    em.flush();
    var cache=session.getProvider(org.keycloak.models.cache.UserCache.class);
    if(cache!=null){var nativeUser=session.users().getUserById(realm,account);if(nativeUser!=null)cache.evict(realm,nativeUser);}
    user.setCreatedTimestamp(null);
    response.getHeaders().putSingle("X-ORISO-Adoption-Null-Timestamp-Fixture-Applied",account);
  }

  public void filter(ContainerRequestContext request, ContainerResponseContext response) {
    String nullAdoption = request.getHeaderString("X-ORISO-Adoption-Null-Timestamp-Fixture");
    if (nullAdoption != null) { nullAdoptionTimestamp(request, response, nullAdoption); return; }
    String operation = request.getHeaderString("X-ORISO-Ready-Fixture");
    if (operation == null) return;
    if (!operation.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        || !"PUT".equals(request.getMethod())
        || !request.getUriInfo().getPath().contains("/otp-config/send-verification-mail/"))
      throw new IllegalStateException("Invalid isolated READY fixture scope");
    var session = KeycloakSessionUtil.getKeycloakSession();
    if (session == null || session.getContext().getRealm() == null
        || !session.getTransactionManager().isActive())
      throw new IllegalStateException("Isolated READY fixture requires active native transaction");
    var realm = session.getContext().getRealm();
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var delivery = em.find(OtpEmailDelivery.class, realm.getId() + ":" + operation);
    var prior = em.find(AccountMaintenanceOperation.class, realm.getId() + ":" + operation);
    if (delivery == null || prior == null || !operation.equals(prior.operationId)
        || !realm.getId().equals(delivery.realmId) || !realm.getId().equals(prior.realmId)
        || !delivery.accountId.equals(prior.accountId) || !"otp.email-start".equals(prior.command)
        || !"READY".equals(delivery.state))
      throw new IllegalStateException("Exact native READY fixture is absent");
    if (response.getStatus() == 202) {
      if (!(response.getEntity() instanceof JsonNode result)
          || !operation.equals(result.path("operationId").asText())
          || !delivery.accountId.equals(result.path("accountId").asText())
          || !"READY".equals(result.path("deliveryState").asText()))
        throw new IllegalStateException("Exact native prepared response is required");
      var user = session.users().getUserById(realm, delivery.accountId);
      if (user == null) throw new IllegalStateException("Exact native fixture user is absent");
      session.sessions().removeUserSessions(realm, user);
      response.getHeaders().putSingle("X-ORISO-Ready-Fixture-Revoked", "true");
    } else if (response.getStatus() != 503)
      throw new IllegalStateException("Unexpected native READY fixture response");
    response.getHeaders().putSingle("X-ORISO-Ready-Fixture-State", "READY");
    response.getHeaders().putSingle("X-ORISO-Ready-Fixture-Tx", "true");
    response.getHeaders().putSingle("X-ORISO-Ready-Fixture-Expired",
        delivery.expiresAt <= java.time.Instant.now().getEpochSecond() ? "true" : "false");
  }
}
