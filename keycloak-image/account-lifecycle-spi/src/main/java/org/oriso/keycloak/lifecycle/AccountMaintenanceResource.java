package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import java.util.Map;
import java.util.Set;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/** Finite bounded read. Mutations deliberately have no route before their own native RED. */
@jakarta.ws.rs.ext.Provider
@jakarta.enterprise.inject.Vetoed
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public final class AccountMaintenanceResource implements RealmResourceProvider {
  private final KeycloakSession session;
  private final LifecycleAuthorization auth;
  private final MaintenanceTarget targets;

  AccountMaintenanceResource(KeycloakSession session, LifecycleAuthorization auth,
      Map<String, Set<String>> mappings) {
    this.session = session;
    this.auth = auth;
    this.targets = new MaintenanceTarget(session, auth, mappings);
  }

  @POST
  @Path("v1/accounts/{account}/read")
  public Response read(@PathParam("account") String account, byte[] raw,
      @HeaderParam("X-ORISO-Task-Context") String proof) {
    try {
      var machine = auth.requireMachine(session, "ACCOUNT_ADMIN");
      var body = parse(raw);
      auth.verifyCommand(proof, machine, "oriso-account-maintenance", "ACCOUNT_MAINTENANCE",
          "account.read", "POST",
          "realm/" + session.getContext().getRealm().getId() + "/account/" + account, body);
      var request = MaintenanceRequest.parse("read", account, body);
      return Response.ok(targets.read(request)).header("Cache-Control", "no-store").build();
    } catch (WebApplicationException failure) {
      session.getTransactionManager().setRollbackOnly();
      throw new WebApplicationException(Response.status(failure.getResponse().getStatus())
          .type(MediaType.APPLICATION_JSON).entity(Map.of("error", "Maintenance request rejected"))
          .header("Cache-Control", "no-store").build());
    } catch (RuntimeException failure) {
      session.getTransactionManager().setRollbackOnly();
      // No token, account body, credential, native exception message or representation is logged.
      org.jboss.logging.Logger.getLogger(AccountMaintenanceResource.class)
          .errorf("Maintenance transaction rolled back: %s", failure.getClass().getName());
      throw new WebApplicationException(Response.status(503).type(MediaType.APPLICATION_JSON)
          .entity(Map.of("error", "Maintenance request could not complete"))
          .header("Cache-Control", "no-store").build());
    }
  }

  public Object getResource() { return this; }
  public void close() {}
}
