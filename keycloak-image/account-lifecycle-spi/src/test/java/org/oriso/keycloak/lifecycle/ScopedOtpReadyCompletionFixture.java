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
  public void filter(ContainerRequestContext request, ContainerResponseContext response) {
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
