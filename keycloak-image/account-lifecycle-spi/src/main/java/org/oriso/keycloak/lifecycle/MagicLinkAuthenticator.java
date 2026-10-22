package org.oriso.keycloak.lifecycle;

import java.util.List;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

/** Native direct-grant claim boundary; deliberately closed until measured native TDD. */
public final class MagicLinkAuthenticator extends AbstractDirectGrantAuthenticator {
  public static final String ID = "oriso-claimed-magic-link";
  public static final String COMMAND = "oriso_magic_command";

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    if (!context.getHttpRequest().getDecodedFormParameters().containsKey(COMMAND)) {
      context.success();
      return;
    }
    context.failure(
        AuthenticationFlowError.INVALID_CREDENTIALS,
        errorResponse(401, "invalid_grant", "Claimed Magic Link session unavailable"));
  }

  @Override
  public String getId() { return ID; }
  @Override
  public String getDisplayType() { return "ORISO claimed Magic Link"; }
  @Override
  public String getReferenceCategory() { return "magic-link"; }
  @Override
  public String getHelpText() { return "Finite native session from an owned claimed Magic Link"; }
  @Override
  public boolean isConfigurable() { return false; }
  @Override
  public boolean isUserSetupAllowed() { return false; }
  @Override
  public Requirement[] getRequirementChoices() { return new Requirement[] {Requirement.REQUIRED}; }
  @Override
  public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
  @Override
  public boolean requiresUser() { return false; }
  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
}
