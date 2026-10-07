package org.oriso.keycloak.commands;

import java.util.Map;
import org.keycloak.events.admin.OperationType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.oriso.keycloak.auth.TaskIdentity;

/** Native events contain only safe identifiers and outcomes, never command credentials. */
final class CommandAudit {
  private CommandAudit() {}

  static void record(
      KeycloakSession session,
      TaskIdentity.Caller caller,
      OperationType operation,
      String resource,
      String path,
      Map<String, ?> representation) {
    var realm = session.getContext().getRealm();
    var auth = new AdminAuth(realm, caller.token(), caller.user(), caller.client());
    new AdminEventBuilder(realm, auth, session, session.getContext().getConnection())
        .operation(operation)
        .resource(resource)
        .resourcePath("oriso-commands", path)
        .representation(representation)
        .success();
  }
}
