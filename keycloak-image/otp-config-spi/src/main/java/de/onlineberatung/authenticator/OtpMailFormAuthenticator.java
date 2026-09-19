package de.onlineberatung.authenticator;

import static de.onlineberatung.authenticator.OtpParameterAuthenticator.extractDecodedOtpParam;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.mail.MailSendingException;
import de.onlineberatung.otp.OtpMailSender;
import de.onlineberatung.otp.OtpService;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

/**
 * Asks for an e-mail one-time code on the BROWSER login flow.
 *
 * <p>{@link OtpMailAuthenticator} does the same job for the direct grant, but it cannot be reused
 * here: it answers with a JSON body over {@code context.failure(...)}, which is what a token
 * request understands and what a browser cannot act on. A browser needs a page to type the code
 * into and a second request that carries it back, which is {@link #authenticate} and {@link
 * #action}. The verdict itself is shared through {@link MailOtpVerifier}.
 *
 * <p>Without this, e-mail is a second factor only where ORISO drives the login itself — the app
 * and the admin panel. Everything that signs in through Keycloak's own pages (Matrix and Element
 * SSO, the account console) runs the built-in {@code auth-otp-form}, which knows only the app
 * credential; for an e-mail-only user its {@code conditional-user-configured} sees nothing
 * configured and the whole subflow is skipped. The user is not stopped — they are waved through
 * with a password alone, which is the failure that looks like success.
 *
 * <p>The form is Keycloak's own one-time-code page, so it inherits the realm's login theme and
 * the message keys every theme already translates. The input is named {@code otp}; {@code totp}
 * is read as well, which is what older themes emit.
 */
public class OtpMailFormAuthenticator implements Authenticator {

  public static final String AUTHENTICATOR_ID = "email-form-authenticator";

  private static final Logger logger = Logger.getLogger(OtpMailFormAuthenticator.class);

  private final OtpService otpService;
  private final MailOtpCredentialService credentialService;
  private final OtpMailSender mailSender;
  private final MailOtpVerifier verifier;

  public OtpMailFormAuthenticator(OtpService otpService,
      MailOtpCredentialService credentialService, OtpMailSender mailSender) {
    this.otpService = otpService;
    this.credentialService = credentialService;
    this.mailSender = mailSender;
    this.verifier = new MailOtpVerifier(otpService, credentialService);
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    var credContext = CredentialContext.fromAuthFlow(context);
    var credentialModel = credentialService.getCredential(credContext);

    if (isNull(credentialModel) || !credentialModel.isActive()) {
      // Nothing to ask for. Stepping aside rather than failing leaves the decision
      // with the flow: a conditional subflow should not have reached us at all, and
      // a misconfigured one must not lock the user out.
      context.attempted();
      return;
    }

    sendCodeAndShowForm(credentialModel, credContext, context);
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    var credContext = CredentialContext.fromAuthFlow(context);
    var submittedCode = extractDecodedOtpParam(context);

    if (isNull(submittedCode) || submittedCode.isBlank()) {
      challengeAgain(context, Messages.MISSING_TOTP);
      return;
    }

    var credentialModel = credentialService.getCredential(credContext);

    switch (verifier.verify(submittedCode, credentialModel, credContext)) {
      case VALID:
        context.success();
        break;
      case EXPIRED:
        challengeAgain(context, Messages.EXPIRED_CODE);
        break;
      case TOO_MANY_FAILED_ATTEMPTS:
        // Past the limit the credential is spent. Re-showing the form would invite
        // an unbounded guessing loop against a six-digit code.
        context.failure(AuthenticationFlowError.ACCESS_DENIED,
            context.form().setError(Messages.ACCOUNT_TEMPORARILY_DISABLED_TOTP)
                .createLoginTotp());
        break;
      default:
        // INVALID and NOT_PRESENT both mean "that code does not open this account".
        // A browser user who mistyped gets the form back; sending them to the
        // password screen for a typo would be its own bug report.
        challengeAgain(context, Messages.INVALID_TOTP);
    }
  }

  private void sendCodeAndShowForm(MailOtpCredentialModel credentialModel,
      CredentialContext credContext, AuthenticationFlowContext context) {
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
      context.challenge(context.form().createLoginTotp());
    } catch (MailSendingException e) {
      // The stored code was already rotated to one nobody received; leaving it live
      // would make the next attempt fail against a code that exists only here.
      credentialService.invalidate(credentialModel, credContext);
      logger.error("failed to send otp mail", e);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR,
          context.form().setError(Messages.COULD_NOT_PROCEED_WITH_AUTHENTICATION_REQUEST)
              .createLoginTotp());
    }
  }

  private void challengeAgain(AuthenticationFlowContext context, String messageKey) {
    context.challenge(context.form().setError(messageKey).createLoginTotp());
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    var credentialModel =
        credentialService.getCredential(new CredentialContext(session, realm, user));
    return nonNull(credentialModel) && credentialModel.isActive();
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    // The factor is established through the SPI's own setup endpoints, not by a
    // required action, so there is nothing to schedule here.
  }

  @Override
  public void close() {
    // no resources held
  }
}
