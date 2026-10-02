package de.onlineberatung.authenticator;

import static de.onlineberatung.authenticator.OtpParameterAuthenticator.extractDecodedOtpParam;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.onlineberatung.mail.MailSendingException;
import de.onlineberatung.otp.MailOtpSendPolicy;
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
  private final MailOtpVerifier verifier;
  private final MailOtpSendPolicy sendPolicy;

  public OtpMailAuthenticator(OtpService otpService, MailOtpCredentialService credentialService,
      OtpMailSender mailSender, MailOtpSendPolicy sendPolicy) {
    this.otpService = otpService;
    this.credentialService = credentialService;
    this.mailSender = mailSender;
    this.sendPolicy = sendPolicy;
    this.verifier = new MailOtpVerifier(otpService, credentialService);
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

  /**
   * Answers a token request that carried no code: normally by mailing a fresh one, but #1338 put two
   * brakes in front of that. A click inside the cooldown must NOT mint a new code — the one in the
   * user's inbox is the one they are about to type, and rotating it is how "I entered the code from
   * the mail and it said invalid" used to happen. The answer stays the same 400 challenge either
   * way, so a client that does not know {@code resendAvailableInSeconds} keeps behaving as before.
   */
  private void sendOtpMail(MailOtpCredentialModel credentialModel, CredentialContext credContext,
      AuthenticationFlowContext context) {

    var decision = sendPolicy.decide(credentialModel);
    if (decision.verdict() == MailOtpSendPolicy.Verdict.CAPPED) {
      logger.warnf("otp mail ceiling reached for keycloak user %s; refusing for %d seconds",
          credContext.getUser().getId(), decision.retryAfterSeconds());
      context.failure(AuthenticationFlowError.ACCESS_DENIED,
          Response.status(Status.TOO_MANY_REQUESTS)
              .entity(challenge(decision.retryAfterSeconds())
                  .errorDescription("Too many codes requested"))
              .type(MediaType.APPLICATION_JSON_TYPE).build());
      return;
    }
    if (decision.verdict() == MailOtpSendPolicy.Verdict.COOLDOWN) {
      context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
          Response.status(Status.BAD_REQUEST)
              .entity(challenge(decision.retryAfterSeconds()).errorDescription("Missing totp"))
              .type(MediaType.APPLICATION_JSON_TYPE).build());
      return;
    }

    var emailAddress = credContext.getUser().getEmail();
    if (isNull(emailAddress) || emailAddress.isBlank()) {
      logger.warn("keycloak user with id " + credContext.getUser().getId()
          + " has no email configured. Will use address from credentials instead");
      emailAddress = credentialModel.getOtp().getEmail();
    }

    var otp = otpService.createOtp(emailAddress);
    // One update carries both: the new code and the record that it was sent. Counting the send in a
    // second write would let a failure between the two leave a limit that silently does not apply.
    credentialModel.updateFrom(otp);
    sendPolicy.recordSent(credentialModel);
    credentialService.update(credentialModel, credContext);

    try {
      mailSender.sendOtpCode(otp, credContext);
      context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
          Response.status(Status.BAD_REQUEST)
              .entity(challenge(decision.retryAfterSeconds()).errorDescription("Missing totp"))
              .type(MediaType.APPLICATION_JSON_TYPE).build());
    } catch (MailSendingException e) {
      credentialService.invalidate(credentialModel, credContext);
      logger.error("failed to send otp mail", e);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR,
          errorResponse(Status.INTERNAL_SERVER_ERROR.getStatusCode(),
              INTERNAL_ERROR, "failed to send otp email"));
    }
  }

  private Challenge challenge(int resendAvailableInSeconds) {
    return new Challenge().error(INVALID_GRANT_ERROR).otpType(OtpType.EMAIL)
        .resendAvailableInSeconds(resendAvailableInSeconds);
  }

  private void validateOtp(String otpRequest, MailOtpCredentialModel credentialModel,
      AuthenticationFlowContext context, CredentialContext credContext) {

    // The verdict and its bookkeeping are shared with the browser-flow authenticator
    // (MailOtpVerifier); only the shape of the answer differs. What is left here is
    // the direct-grant answer: a JSON body a token client can read.
    switch (verifier.verify(otpRequest, credentialModel, credContext)) {
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
