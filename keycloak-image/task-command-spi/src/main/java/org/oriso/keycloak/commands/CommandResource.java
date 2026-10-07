package org.oriso.keycloak.commands;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.oriso.keycloak.auth.OriginAuthorization;

@jakarta.ws.rs.ext.Provider
@jakarta.enterprise.inject.Vetoed
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public final class CommandResource implements RealmResourceProvider {
  private final AccountCommands accounts;
  private final SmtpCommands smtp;
  private final InventoryCommands inventory;
  private final LifecycleCommands lifecycle;

  CommandResource(KeycloakSession session, OriginAuthorization origins) {
    accounts = new AccountCommands(session, origins);
    smtp = new SmtpCommands(session, origins);
    inventory = new InventoryCommands(session, origins);
    lifecycle = new LifecycleCommands(session, origins);
  }

  @PUT
  @Path("v1/account-creations/{attemptId}")
  public Response create(
      @PathParam("attemptId") String attempt,
      JsonNode body,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return accounts.create(attempt, body, origin);
  }

  @POST
  @Path("v1/account-creations/{attemptId}/commit")
  public Response commit(
      @PathParam("attemptId") String attempt,
      JsonNode body,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return accounts.finish(attempt, body, origin, true);
  }

  @POST
  @Path("v1/account-creations/{attemptId}/compensations")
  public Response compensate(
      @PathParam("attemptId") String attempt,
      JsonNode body,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return accounts.finish(attempt, body, origin, false);
  }

  @GET
  @Path("v1/accounts/{accountId}")
  public Response read(
      @PathParam("accountId") String account,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return accounts.read(account, origin);
  }

  @GET
  @Path("v1/accounts/search")
  public Response search(
      @QueryParam("username") String username,
      @QueryParam("email") String email,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return accounts.search(username, email, origin);
  }

  @PATCH
  @Path("v1/accounts/{accountId}/profile")
  public Response profile(
      @PathParam("accountId") String account,
      JsonNode body,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return accounts.profile(account, body, origin);
  }

  @PUT
  @Path("v1/accounts/{accountId}/password")
  public Response password(
      @PathParam("accountId") String account,
      JsonNode body,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return accounts.password(account, body, origin);
  }

  @PUT
  @Path("v1/accounts/{accountId}/roles")
  public Response roles(
      @PathParam("accountId") String account,
      JsonNode body,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return accounts.updateRoles(account, body, origin);
  }

  @POST
  @Path("v1/accounts/{accountId}/deactivation")
  public Response deactivate(
      @PathParam("accountId") String account,
      JsonNode body,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return accounts.lifecycle(account, body, origin, false);
  }

  @DELETE
  @Path("v1/accounts/{accountId}")
  public Response delete(
      @PathParam("accountId") String account,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return accounts.lifecycle(account, OriginAuthorization.JSON.createObjectNode(), origin, true);
  }

  @POST
  @Path("v1/account-inventory")
  public Response inventory(
      JsonNode body, @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return inventory.read(body, origin);
  }

  @GET
  @Path("v1/accounts/{accountId}/lifecycle-status")
  public Response lifecycleStatus(
      @PathParam("accountId") String account,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return lifecycle.status(account, origin);
  }

  @POST
  @Path("v1/accounts/{accountId}/suspension")
  public Response suspend(
      @PathParam("accountId") String account,
      JsonNode body,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return lifecycle.access(account, body, origin, false);
  }

  @POST
  @Path("v1/accounts/{accountId}/access-restoration")
  public Response restore(
      @PathParam("accountId") String account,
      JsonNode body,
      @HeaderParam("X-ORISO-Origin-Authorization") String origin) {
    return lifecycle.access(account, body, origin, true);
  }

  @PUT
  @Path("v1/smtp")
  public Response smtp(JsonNode body) {
    return smtp.apply(body);
  }

  public Object getResource() {
    return this;
  }

  public void close() {}
}
