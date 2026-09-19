package de.onlineberatung.authenticator;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.mail.MailSendingException;
import de.onlineberatung.otp.Otp;
import de.onlineberatung.otp.OtpMailSender;
import de.onlineberatung.otp.OtpService;
import de.onlineberatung.otp.ValidationResult;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import java.time.Clock;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * The browser counterpart to {@code OtpMailAuthenticator}.
 *
 * <p>The direct-grant one answers a token request with a JSON challenge, which a browser cannot
 * act on — there is no form to type the code into and no second request to receive it. Without
 * this authenticator a counsellor whose second factor is e-mail is asked for no second factor at
 * all on any browser login, because the built-in {@code auth-otp-form} only knows the app
 * credential.
 */
public class OtpMailFormAuthenticatorTest {

  private AuthenticationFlowContext authFlow;
  private OtpMailSender mailSender;
  private OtpService otpService;
  private MailOtpCredentialService credentialService;
  private LoginFormsProvider form;
  private Response formResponse;
  private MultivaluedHashMap<String, String> decodedFormParams;
  private UserModel user;
  private MailOtpCredentialModel activeCredential;
  private OtpMailFormAuthenticator authenticator;

  @Before
  public void setUp() {
    authFlow = mock(AuthenticationFlowContext.class);
    var httpRequest = mock(HttpRequest.class);
    when(authFlow.getHttpRequest()).thenReturn(httpRequest);
    decodedFormParams = new MultivaluedHashMap<>();
    when(httpRequest.getDecodedFormParameters()).thenReturn(decodedFormParams);

    var realm = mock(RealmModel.class);
    when(authFlow.getRealm()).thenReturn(realm);
    when(authFlow.getSession()).thenReturn(mock(KeycloakSession.class));
    user = mock(UserModel.class);
    when(authFlow.getUser()).thenReturn(user);
    when(user.getEmail()).thenReturn("counsellor@example.org");

    form = mock(LoginFormsProvider.class);
    formResponse = mock(Response.class);
    when(authFlow.form()).thenReturn(form);
    when(form.setError(anyString())).thenReturn(form);
    when(form.createLoginTotp()).thenReturn(formResponse);

    mailSender = mock(OtpMailSender.class);
    otpService = mock(OtpService.class);
    credentialService = mock(MailOtpCredentialService.class);

    activeCredential =
        MailOtpCredentialModel.createOtpModel(
            new Otp("1234", 300, 1000L, "counsellor@example.org", 0),
            Clock.systemDefaultZone(),
            true);
    when(credentialService.getCredential(any(CredentialContext.class)))
        .thenReturn(activeCredential);
    when(otpService.createOtp(anyString()))
        .thenReturn(new Otp("5678", 300, 2000L, "counsellor@example.org", 0));

    authenticator = new OtpMailFormAuthenticator(otpService, credentialService, mailSender);
  }

  @Test
  public void authenticate_should_mail_a_code_and_show_the_form() throws Exception {
    authenticator.authenticate(authFlow);

    verify(mailSender).sendOtpCode(any(Otp.class), any(CredentialContext.class));
    verify(authFlow).challenge(formResponse);
    verify(authFlow, never()).success();
  }

  @Test
  public void authenticate_should_fail_the_flow_when_the_mail_cannot_be_sent() throws Exception {
    org.mockito.Mockito.doThrow(new MailSendingException("smtp down", null))
        .when(mailSender)
        .sendOtpCode(any(Otp.class), any(CredentialContext.class));

    authenticator.authenticate(authFlow);

    verify(credentialService).invalidate(eq(activeCredential), any(CredentialContext.class));
    verify(authFlow).failure(eq(AuthenticationFlowError.INTERNAL_ERROR), any(Response.class));
  }

  @Test
  public void authenticate_should_step_aside_when_no_active_credential_exists() {
    when(credentialService.getCredential(any(CredentialContext.class))).thenReturn(null);

    authenticator.authenticate(authFlow);

    verify(authFlow).attempted();
    verify(authFlow, never()).challenge(any(Response.class));
  }

  @Test
  public void action_should_let_a_correct_code_through() {
    decodedFormParams.putSingle("otp", "1234");
    when(otpService.validate(eq("1234"), any(Otp.class))).thenReturn(ValidationResult.VALID);

    authenticator.action(authFlow);

    verify(authFlow).success();
  }

  @Test
  public void action_should_read_the_legacy_totp_field_too() {
    decodedFormParams.putSingle("totp", "1234");
    when(otpService.validate(eq("1234"), any(Otp.class))).thenReturn(ValidationResult.VALID);

    authenticator.action(authFlow);

    verify(authFlow).success();
  }

  @Test
  public void action_should_let_a_wrong_code_be_retried_on_the_form() {
    // A browser user mistypes; re-showing the form with an error is the whole
    // point of a form. Hard-failing the flow would send them back to the
    // password screen for a typo.
    decodedFormParams.putSingle("otp", "9999");
    when(otpService.validate(eq("9999"), any(Otp.class))).thenReturn(ValidationResult.INVALID);

    authenticator.action(authFlow);

    verify(form).setError(anyString());
    verify(authFlow).challenge(formResponse);
    verify(authFlow, never()).success();
  }

  @Test
  public void action_should_let_an_expired_code_be_retried_on_the_form() {
    decodedFormParams.putSingle("otp", "1234");
    when(otpService.validate(eq("1234"), any(Otp.class))).thenReturn(ValidationResult.EXPIRED);

    authenticator.action(authFlow);

    verify(form).setError(anyString());
    verify(authFlow).challenge(formResponse);
    verify(authFlow, never()).success();
  }

  @Test
  public void action_should_ask_again_when_nothing_was_typed() {
    authenticator.action(authFlow);

    verify(form).setError(anyString());
    verify(authFlow).challenge(formResponse);
    verify(authFlow, never()).success();
  }

  @Test
  public void action_should_stop_the_flow_once_the_attempt_limit_is_reached() {
    // Past the limit the credential is spent; letting the form reappear would
    // invite an unbounded guessing loop.
    decodedFormParams.putSingle("otp", "9999");
    when(otpService.validate(eq("9999"), any(Otp.class)))
        .thenReturn(ValidationResult.TOO_MANY_FAILED_ATTEMPTS);

    authenticator.action(authFlow);

    verify(authFlow).failure(eq(AuthenticationFlowError.ACCESS_DENIED), any(Response.class));
    verify(authFlow, never()).success();
  }

  @Test
  public void isConfigured_should_follow_the_active_credential() {
    var session = mock(KeycloakSession.class);
    var realm = mock(RealmModel.class);

    assertThat(authenticator.configuredFor(session, realm, user)).isTrue();

    when(credentialService.getCredential(any(CredentialContext.class))).thenReturn(null);
    assertThat(authenticator.configuredFor(session, realm, user)).isFalse();
  }

  @Test
  public void requiresUser_should_be_true_because_the_factor_belongs_to_an_identified_user() {
    assertThat(authenticator.requiresUser()).isTrue();
  }
}
