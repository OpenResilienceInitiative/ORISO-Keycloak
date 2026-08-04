package de.onlineberatung.authenticator;

import static java.util.Objects.isNull;

import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import java.util.Collections;
import java.util.List;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

public class OtpParameterAuthenticator extends AbstractDirectGrantAuthenticator {

  public static final String ID = "otp-parameter-authenticator";

  static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED};

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    String otpOfRequest = extractDecodedOtpParam(context);

    // blank counts as missing, mirroring OtpMailAuthenticator — otherwise an empty
    // otp param would skip the challenge and fail downstream without the otpType hint
    if (otpOfRequest == null || otpOfRequest.isBlank()) {
      Challenge challengeResponse = new Challenge().error("invalid_grant")
          .errorDescription("Missing totp").otpType(OtpType.APP);
      context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
          Response.status(Status.BAD_REQUEST).entity(challengeResponse)
              .type(MediaType.APPLICATION_JSON_TYPE).build());
      return;
    }
    context.success();
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel,
      UserModel userModel) {
    return userModel.credentialManager().isConfiguredFor(OTPCredentialModel.TYPE);
  }

  @Override
  public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel,
      UserModel userModel) {
    // Nothing to do here because configuredFor always returns true
  }

  @Override
  public String getDisplayType() {
    return "OTP parameter validator";
  }

  @Override
  public String getReferenceCategory() {
    return "otp";
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return "Validates if the otp parameter is set when OTP is enabled for the user";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return Collections.emptyList();
  }

  static String extractDecodedOtpParam(AuthenticationFlowContext context) {
    var inputData = context.getHttpRequest().getDecodedFormParameters();
    var otpParam = inputData.getFirst("otp");
    otpParam = (isNull(otpParam)) ? inputData.getFirst("totp") : otpParam;
    return otpParam;
  }
}
