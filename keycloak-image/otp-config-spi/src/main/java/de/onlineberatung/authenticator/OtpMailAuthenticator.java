package de.onlineberatung.authenticator;

import static de.onlineberatung.authenticator.OtpParameterAuthenticator.extractDecodedOtpParam;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.onlineberatung.otp.OtpMailSender;
import de.onlineberatung.otp.OtpMailThrottle;
import de.onlineberatung.otp.OtpService;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import java.time.Clock;
import java.util.Collections;
import java.util.List;
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

  private static final String INVALID_GRANT_ERROR = "invalid_grant";
  private static final String INTERNAL_ERROR = "internal_error";

  private static final String TOO_MANY_CODES = "Too many codes requested";

  private final MailOtpCredentialService credentialService;
  private final MailOtpVerifier verifier;
  private final MailOtpIssuer issuer;

  /** Cooldown and cap at their defaults; kept for callers that do not configure them. */
  public OtpMailAuthenticator(OtpService otpService, MailOtpCredentialService credentialService,
      OtpMailSender mailSender) {
    this(otpService, credentialService, mailSender,
        OtpMailThrottle.fromConfig(Clock.systemDefaultZone(), null));
  }

  public OtpMailAuthenticator(OtpService otpService, MailOtpCredentialService credentialService,
      OtpMailSender mailSender, OtpMailThrottle throttle) {
    this.credentialService = credentialService;
    this.verifier = new MailOtpVerifier(otpService, credentialService);
    this.issuer = new MailOtpIssuer(otpService, credentialService, mailSender, throttle);
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

    var outcome = issuer.issue(credentialModel, credContext);
    switch (outcome.getResult()) {
      case SENT:
      case KEPT:
        // Same challenge whether or not a mail went out: inside the cooldown the code the
        // user already has stays valid, and resendAvailableInSeconds says when asking again
        // will mail a new one. Clients that do not know the field see the old answer.
        context.challenge(challenge(Status.BAD_REQUEST, "Missing totp", outcome));
        break;
      case LIMIT_REACHED:
        context.challenge(
            Response.fromResponse(challenge(Status.TOO_MANY_REQUESTS, TOO_MANY_CODES, outcome))
                .header(HttpHeaders.RETRY_AFTER, outcome.getResendAvailableInSeconds())
                .build());
        break;
      default:
        context.challenge(errorResponse(Status.INTERNAL_SERVER_ERROR.getStatusCode(),
            INTERNAL_ERROR, "failed to send otp email"));
    }
  }

  private static Response challenge(Status status, String description,
      MailOtpIssuer.Outcome outcome) {
    var body = new Challenge().error(INVALID_GRANT_ERROR).errorDescription(description)
        .otpType(OtpType.EMAIL)
        .resendAvailableInSeconds(Math.toIntExact(outcome.getResendAvailableInSeconds()));
    return Response.status(status).entity(body).type(MediaType.APPLICATION_JSON_TYPE).build();
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
