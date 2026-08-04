package de.onlineberatung.authenticator;

import static java.time.Clock.systemDefaultZone;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.onlineberatung.mail.MailSendingException;
import de.onlineberatung.otp.Otp;
import de.onlineberatung.otp.OtpMailSender;
import de.onlineberatung.otp.OtpService;
import de.onlineberatung.otp.ValidationResult;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType;
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
import org.mockito.Mockito;

public class OtpMailAuthenticatorTest {

  private AuthenticationFlowContext authFlow;
  private OtpMailSender mailSender;
  private OtpService otpService;
  private KeycloakSession session;
  private RealmModel realm;
  private MailOtpCredentialService credentialService;
  private CredentialContext credentialContext;
  private UserModel user;
  private MultivaluedHashMap<String, String> decodedFormParams;
  private OtpMailAuthenticator authenticator;

  @Before
  public void setUp() {
    authFlow = mock(AuthenticationFlowContext.class);
    var httpRequest = mock(HttpRequest.class);
    when(authFlow.getHttpRequest()).thenReturn(httpRequest);
    decodedFormParams = new MultivaluedHashMap<>();
    when(httpRequest.getDecodedFormParameters()).thenReturn(decodedFormParams);
    mailSender = mock(OtpMailSender.class);
    otpService = mock(OtpService.class);
    realm = mock(RealmModel.class);
    when(authFlow.getRealm()).thenReturn(realm);
    session = mock(KeycloakSession.class);
    when(authFlow.getSession()).thenReturn(session);
    user = mock(UserModel.class);
    when(authFlow.getUser()).thenReturn(user);
    credentialService = mock(MailOtpCredentialService.class);
    credentialContext = new CredentialContext(session, realm, user);
    authenticator = new OtpMailAuthenticator(otpService, credentialService, mailSender);
  }

  @Test
  public void isConfigured_should_be_true_if_credential_is_active() {
    var otp = new Otp("1234", 300, 1000L, "someemail@test.de", 0);
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, systemDefaultZone(), true);
    when(credentialService.getCredential(credentialContext)).thenReturn(credentialModel);

    var configured = authenticator.configuredFor(session, realm, user);

    assertThat(configured).isTrue();
  }

  @Test
  public void isConfigured_should_be_false_if_credential_is_inactive() {
    var otp = new Otp("1234", 300, 1000L, "someemail@test.de", 0);
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, systemDefaultZone(), false);
    when(credentialService.getCredential(credentialContext)).thenReturn(credentialModel);

    var configured = authenticator.configuredFor(session, realm, user);

    assertThat(configured).isFalse();
  }

  @Test
  public void isConfigured_should_be_false_if_credentials_are_not_set() {
    var configured = authenticator.configuredFor(session, realm, user);

    assertThat(configured).isFalse();
  }

  @Test
  public void authenticate_should_send_mail_if_otp_param_is_missing() {
    when(user.getUsername()).thenReturn("Karen");
    when(user.getEmail()).thenReturn("mymail@test.de");
    var expectedOtp = new Otp("123", 200L, 123456L, "mymail@test.de", 0);
    var credentialModel = MailOtpCredentialModel.createOtpModel(expectedOtp, systemDefaultZone());
    when(credentialService.getCredential(credentialContext)).thenReturn(credentialModel);
    when(otpService.createOtp("mymail@test.de")).thenReturn(expectedOtp);

    authenticator.authenticate(authFlow);

    var responseCaptor = ArgumentCaptor.forClass(Response.class);
    verify(authFlow).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS),
        responseCaptor.capture());
    assertThat(responseCaptor.getValue().getStatus()).isEqualTo(400);
    var challenge = responseCaptor.getValue().readEntity(Challenge.class);
    assertThat(challenge.getOtpType()).isEqualTo(OtpType.EMAIL);
    verify(mailSender).sendOtpCode(expectedOtp, credentialContext);
  }

  @Test
  public void authenticate_should_use_email_address_from_stored_credentials_if_user_has_none() {
    when(user.getUsername()).thenReturn("Karen");
    var expectedOtp = new Otp("123", 200L, 123456L, "mymail@test.de", 0);
    var credentialModel = MailOtpCredentialModel.createOtpModel(expectedOtp, systemDefaultZone());
    when(credentialService.getCredential(credentialContext)).thenReturn(credentialModel);
    when(otpService.createOtp("mymail@test.de")).thenReturn(expectedOtp);

    authenticator.authenticate(authFlow);

    var responseCaptor = ArgumentCaptor.forClass(Response.class);
    verify(authFlow).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS),
        responseCaptor.capture());
    assertThat(responseCaptor.getValue().getStatus()).isEqualTo(400);
    var challenge = responseCaptor.getValue().readEntity(Challenge.class);
    assertThat(challenge.getOtpType()).isEqualTo(OtpType.EMAIL);
    verify(mailSender).sendOtpCode(expectedOtp, credentialContext);
  }

  @Test
  public void authenticate_should_invalidate_otp_if_mail_sending_fails() {
    when(user.getUsername()).thenReturn("Karen");
    when(user.getEmail()).thenReturn("mymail@test.de");
    var expectedOtp = new Otp("123", 200L, 123456L, "mymail@test.de", 0);
    when(otpService.createOtp("mymail@test.de")).thenReturn(expectedOtp);
    var credentialModel = MailOtpCredentialModel.createOtpModel(expectedOtp, systemDefaultZone());
    when(credentialService.getCredential(credentialContext)).thenReturn(credentialModel);
    Mockito.doThrow(MailSendingException.class).when(mailSender).sendOtpCode(any(), any());

    authenticator.authenticate(authFlow);

    var responseCaptor = ArgumentCaptor.forClass(Response.class);
    verify(authFlow).failure(eq(AuthenticationFlowError.INTERNAL_ERROR),
        responseCaptor.capture());
    assertThat(responseCaptor.getValue().getStatus()).isEqualTo(500);
    verify(credentialService).invalidate(credentialModel, credentialContext);
  }

  @Test
  public void authenticate_should_increase_number_of_failed_attempts_if_otp_is_invalid() {
    when(user.getUsername()).thenReturn("Karen");
    when(user.getEmail()).thenReturn("mymail@test.de");
    var storedOtp = new Otp("123", 200L, 123456L, "mymail@test.de", 0);
    var credentialModel = MailOtpCredentialModel.createOtpModel(storedOtp, systemDefaultZone());
    when(credentialService.getCredential(credentialContext)).thenReturn(credentialModel);
    decodedFormParams.put("otp", singletonList("86767"));
    when(otpService.validate("86767", storedOtp)).thenReturn(ValidationResult.INVALID);

    authenticator.authenticate(authFlow);

    verify(credentialService).incrementFailedAttempts(credentialModel, credentialContext, 0);
  }
}
