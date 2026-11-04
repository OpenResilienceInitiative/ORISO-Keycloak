package org.oriso.keycloak.lifecycle;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

/** Common factory lifecycle for the three finite native flow executions. */
abstract class MagicLinkFlow extends AbstractDirectGrantAuthenticator {
  MagicLinkAuthority authority;
  void refuse(AuthenticationFlowContext context, RuntimeException failure) {
    // Deliberately omit messages, causes, request data and locals even in private server logs.
    var trace = new StringBuilder(failure.getClass().getName());
    for (var frame : failure.getStackTrace()) {
      if (frame.getClassName().startsWith("org.oriso.keycloak.lifecycle.") && frame.getLineNumber()>0)
        trace.append("\n at ").append(frame);
    }
    org.jboss.logging.Logger.getLogger(MagicLinkFlow.class).warn(trace.toString());
    context.getSession().getTransactionManager().setRollbackOnly();
    context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,errorResponse(401,"invalid_grant","Claimed Magic Link unavailable"));
  }
  public void init(Config.Scope config) { authority = MagicLinkAuthority.environment(); }
  public String getReferenceCategory() { return "magic-link"; }
  public String getHelpText() { return "Native session from a checked privately claimed Magic Link"; }
  public boolean isConfigurable() { return false; }
  public boolean isUserSetupAllowed() { return false; }
  public Requirement[] getRequirementChoices() { return new Requirement[] {Requirement.REQUIRED}; }
  public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
  public boolean requiresUser() { return false; }
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
}
