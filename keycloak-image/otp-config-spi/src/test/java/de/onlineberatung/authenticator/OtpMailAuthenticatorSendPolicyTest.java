package de.onlineberatung.authenticator;

import static java.time.Clock.systemDefaultZone;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType;
import de.onlineberatung.otp.MailOtpSendPolicy;
import de.onlineberatung.otp.Otp;
import de.onlineberatung.otp.OtpMailSender;
import de.onlineberatung.otp.OtpService;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.ArgumentCaptor;

/**
 * What a token client sees when it asks for a code too often (ORISO-UserService#1338).
 *
 * <p>Separate from {@link OtpMailAuthenticatorTest} because these tests need a policy that actually
 * refuses; that test deliberately uses a permissive one so it keeps asserting the happy path.
 */
public class OtpMailAuthenticatorSendPolicyTest {

  private AuthenticationFlowContext authFlow;
  private OtpMailSender mailSender;
  private OtpService otpService;
  private MailOtpCredentialService credentialService;
  private CredentialContext credentialContext;
  private UserModel user;

  @Before
  public void setUp() {
    authFlow = mock(AuthenticationFlowContext.class);
    var httpRequest = mock(HttpRequest.class);
    when(authFlow.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getDecodedFormParameters()).thenReturn(new MultivaluedHashMap<>());
    mailSender = mock(OtpMailSender.class);
    otpService = mock(OtpService.class);
    var realm = mock(RealmModel.class);
    when(authFlow.getRealm()).thenReturn(realm);
    var session = mock(KeycloakSession.class);
    when(authFlow.getSession()).thenReturn(session);
    user = mock(UserModel.class);
    when(user.getId()).thenReturn("kc-user-1");
    when(user.getEmail()).thenReturn("berater@example.org");
    when(authFlow.getUser()).thenReturn(user);
    credentialService = mock(MailOtpCredentialService.class);
    credentialContext = new CredentialContext(session, realm, user);
  }

  private OtpMailAuthenticator authenticatorWith(MailOtpSendPolicy policy) {
    return new OtpMailAuthenticator(otpService, credentialService, mailSender, policy);
  }

  private MailOtpCredentialModel storedCredential() {
    var otp = new Otp("123456", 900L, 123456L, "berater@example.org", 0);
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, systemDefaultZone(), true);
    when(credentialService.getCredential(credentialContext)).thenReturn(credentialModel);
    when(otpService.createOtp("berater@example.org"))
        .thenReturn(new Otp("654321", 900L, 123456L, "berater@example.org", 0));
    return credentialModel;
  }

  @Test
  public void authenticate_tells_the_client_how_long_to_wait_before_the_next_code() {
    var credentialModel = storedCredential();

    authenticatorWith(new MailOtpSendPolicy(systemDefaultZone(), null)).authenticate(authFlow);

    var challenge = capturedChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, 400);
    assertThat(challenge.getOtpType()).isEqualTo(OtpType.EMAIL);
    assertThat(challenge.getResendAvailableInSeconds())
        .isEqualTo(MailOtpSendPolicy.DEFAULT_COOLDOWN_SECONDS);
    // the send is recorded on the same model that is stored, so the limits survive the request
    assertThat(credentialModel.getMailsSentInWindow()).isEqualTo(1);
    verify(credentialService).update(credentialModel, credentialContext);
  }

  @Test
  public void authenticate_sends_no_second_mail_inside_the_cooldown_and_keeps_the_code() {
    var credentialModel = storedCredential();
    var policy = new MailOtpSendPolicy(systemDefaultZone(), null);
    policy.recordSent(credentialModel);
    var codeInTheUsersInbox = credentialModel.getOtp().getCode();

    authenticatorWith(policy).authenticate(authFlow);

    var challenge = capturedChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, 400);
    // same 400 challenge as before #1338, so a client that ignores the new field behaves as it did
    assertThat(challenge.getErrorDescription()).isEqualTo("Missing totp");
    assertThat(challenge.getResendAvailableInSeconds()).isGreaterThan(0);
    verify(mailSender, never()).sendOtpCode(any(), any());
    verify(credentialService, never()).update(any(), any());
    assertThat(credentialModel.getOtp().getCode()).isEqualTo(codeInTheUsersInbox);
  }

  @Test
  public void authenticate_answers_429_once_the_ceiling_is_reached() {
    var credentialModel = storedCredential();
    var policy = new MailOtpSendPolicy(systemDefaultZone(), null);
    for (var i = 0; i < MailOtpSendPolicy.DEFAULT_MAX_SENDS_PER_WINDOW; i++) {
      policy.recordSent(credentialModel);
    }
    // put the last send far enough back that the cooldown is not what refuses here
    credentialModel.applySendBookkeeping(
        System.currentTimeMillis() - 60_000L,
        credentialModel.getSendWindowStartedAt(),
        credentialModel.getMailsSentInWindow());

    authenticatorWith(policy).authenticate(authFlow);

    var challenge = capturedChallenge(AuthenticationFlowError.ACCESS_DENIED, 429);
    assertThat(challenge.getErrorDescription()).isEqualTo("Too many codes requested");
    assertThat(challenge.getResendAvailableInSeconds()).isGreaterThan(0);
    verify(mailSender, never()).sendOtpCode(any(), any());
    verify(credentialService, never()).update(any(), any());
  }

  private Challenge capturedChallenge(AuthenticationFlowError expectedError, int expectedStatus) {
    var responseCaptor = ArgumentCaptor.forClass(Response.class);
    verify(authFlow).failure(eq(expectedError), responseCaptor.capture());
    assertThat(responseCaptor.getValue().getStatus()).isEqualTo(expectedStatus);
    return responseCaptor.getValue().readEntity(Challenge.class);
  }
}
