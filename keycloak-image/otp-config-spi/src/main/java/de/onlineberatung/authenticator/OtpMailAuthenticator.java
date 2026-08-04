package de.onlineberatung.authenticator;

import static de.onlineberatung.authenticator.OtpParameterAuthenticator.extractDecodedOtpParam;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.onlineberatung.mail.MailSendingException;
import de.onlineberatung.otp.OtpMailSender;
import de.onlineberatung.otp.OtpService;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import java.util.Collections;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

public class OtpMailAuthenticator extends AbstractDirectGrantAuthenticator {

  public static final String AUTHENTICATOR_ID = "email-authenticator";

  private static final Logger logger = Logger.getLogger(OtpMailAuthenticator.class);
  private static final String INVALID_GRANT_ERROR = "invalid_grant";
  private static final String INTERNAL_ERROR = "internal_error";

  private final OtpService otpService;
  private final MailOtpCredentialService credentialService;
  private final OtpMailSender mailSender;

  public OtpMailAuthenticator(OtpService otpService, MailOtpCredentialService credentialService,
      OtpMailSender mailSender) {
    this.otpService = otpService;
    this.credentialService = credentialService;
    this.mailSender = mailSender;
  }

  @Override
  public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel,
      UserModel userModel) {
    var context = new CredentialContext(keycloakSession, realmModel, userModel);
    var credentialModel = credentialService.getCredential(context);
    return nonNull(credentialModel) && credentialModel.isActive();
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    var credContext = CredentialContext.fromAuthFlow(context);
    var credentialModel = credentialService.getCredential(credContext);

    var otpOfRequest = extractDecodedOtpParam(context);
    if (isNull(otpOfRequest) || otpOfRequest.isBlank()) {
      sendOtpMail(credentialModel, credContext, context);
      return;
    }

    validateOtp(otpOfRequest, credentialModel, context, credContext);
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // unused
  }

  private void sendOtpMail(MailOtpCredentialModel credentialModel, CredentialContext credContext,
      AuthenticationFlowContext context) {

    var emailAddress = credContext.getUser().getEmail();
    if (isNull(emailAddress) || emailAddress.isBlank()) {
      logger.warn("keycloak user with id " + credContext.getUser().getId()
          + " has no email configured. Will use address from credentials instead");
      emailAddress = credentialModel.getOtp().getEmail();
    }

    var otp = otpService.createOtp(emailAddress);
    credentialService.update(credentialModel.updateFrom(otp), credContext);

    try {
      mailSender.sendOtpCode(otp, credContext);
      var challengeResponse = new Challenge().error(INVALID_GRANT_ERROR)
          .errorDescription("Missing totp").otpType(OtpType.EMAIL);
      context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
          Response.status(Status.BAD_REQUEST).entity(challengeResponse)
              .type(MediaType.APPLICATION_JSON_TYPE).build());
    } catch (MailSendingException e) {
      credentialService.invalidate(credentialModel, credContext);
      logger.error("failed to send otp mail", e);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR,
          errorResponse(Status.INTERNAL_SERVER_ERROR.getStatusCode(),
              INTERNAL_ERROR, "failed to send otp email"));
    }
  }

  private void validateOtp(String otpRequest, MailOtpCredentialModel credentialModel,
      AuthenticationFlowContext context, CredentialContext credContext) {

    var otp = credentialModel.getOtp();

    switch (otpService.validate(otpRequest, otp)) {
      case NOT_PRESENT:
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
            errorResponse(Status.UNAUTHORIZED.getStatusCode(),
                INVALID_GRANT_ERROR, "No corresponding code"));
        break;
      case EXPIRED:
        context.failure(AuthenticationFlowError.EXPIRED_CODE,
            errorResponse(Status.UNAUTHORIZED.getStatusCode(),
                INVALID_GRANT_ERROR, "Code expired"));
        break;
      case INVALID:
        credentialService.incrementFailedAttempts(credentialModel, credContext,
            otp.getFailedVerifications());
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
            errorResponse(Status.UNAUTHORIZED.getStatusCode(),
                INVALID_GRANT_ERROR, "Invalid code"));
        break;
      case TOO_MANY_FAILED_ATTEMPTS:
        context.failure(AuthenticationFlowError.ACCESS_DENIED,
            errorResponse(Status.TOO_MANY_REQUESTS.getStatusCode(),
                INVALID_GRANT_ERROR, "Maximal number of failed attempts reached"));
        break;
      case VALID:
        credentialService.invalidate(credentialModel, credContext);
        context.success();
        break;
      default:
        context.failure(AuthenticationFlowError.INTERNAL_ERROR,
            errorResponse(Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                INTERNAL_ERROR, "failed to validate code"));
    }
  }

  @Override
  public String getDisplayType() {
    return null;
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
    return new Requirement[0];
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public String getHelpText() {
    return null;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return Collections.emptyList();
  }

  @Override
  public String getId() {
    return null;
  }
}
