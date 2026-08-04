package de.onlineberatung.authenticator;

import static java.time.Clock.systemDefaultZone;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.otp.Otp;
import de.onlineberatung.otp.OtpMailSender;
import de.onlineberatung.otp.OtpService;
import de.onlineberatung.otp.ValidationResult;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.ArgumentCaptor;

@RunWith(Parameterized.class)
public class OtpMailAuthenticatorParameterizedTest {

  private MailOtpCredentialService credentialService;
  private CredentialContext credentialContext;

  @Parameters(name = "Test {index}: authenticate ValidationResult{0} = http {1} flowError {2}")
  public static Collection<Object[]> data() {
    return Arrays.asList(new Object[][]{
        {ValidationResult.VALID, 201, null},
        {ValidationResult.INVALID, 401, AuthenticationFlowError.INVALID_CREDENTIALS},
        {ValidationResult.NOT_PRESENT, 401, AuthenticationFlowError.INVALID_CREDENTIALS},
        {ValidationResult.TOO_MANY_FAILED_ATTEMPTS, 429, AuthenticationFlowError.ACCESS_DENIED},
        {ValidationResult.EXPIRED, 401, AuthenticationFlowError.EXPIRED_CODE}
    });
  }


  public OtpMailAuthenticatorParameterizedTest(ValidationResult input, int httpStatusExpected,
      AuthenticationFlowError flowError) {
    this.input = input;
    this.httpStatusExpected = httpStatusExpected;
    this.flowError = flowError;
  }

  private final ValidationResult input;
  private final int httpStatusExpected;
  private final AuthenticationFlowError flowError;
  private AuthenticationFlowContext authFlow;
  private OtpService otpService;
  private OtpMailAuthenticator authenticator;

  @Before
  public void setUp() {
    authFlow = mock(AuthenticationFlowContext.class);
    var httpRequest = mock(HttpRequest.class);
    when(authFlow.getHttpRequest()).thenReturn(httpRequest);
    MultivaluedHashMap<String, String> decodedFormParams = new MultivaluedHashMap<>();
    decodedFormParams.put("otp", Collections.singletonList("765432"));
    when(httpRequest.getDecodedFormParameters()).thenReturn(decodedFormParams);
    otpService = mock(OtpService.class);
    RealmModel realm = mock(RealmModel.class);
    when(authFlow.getRealm()).thenReturn(realm);
    UserModel user = mock(UserModel.class);
    when(user.getUsername()).thenReturn("katharina");
    when(authFlow.getUser()).thenReturn(user);
    KeycloakSession session = mock(KeycloakSession.class);
    when(authFlow.getSession()).thenReturn(session);
    credentialService = mock(MailOtpCredentialService.class);
    credentialContext = new CredentialContext(session, realm, user);
    authenticator = new OtpMailAuthenticator(otpService, credentialService,
        mock(OtpMailSender.class));
  }

  @Test
  public void authenticate_otp_validation() {
    var otp = new Otp("765432", 11L, 112L, null, 0);
    MailOtpCredentialModel credentialModel = MailOtpCredentialModel
        .createOtpModel(otp, systemDefaultZone());
    when(credentialService.getCredential(credentialContext)).thenReturn(credentialModel);
    when(otpService.validate("765432", otp)).thenReturn(input);

    authenticator.authenticate(authFlow);

    var responseCaptor = ArgumentCaptor.forClass(Response.class);
    if (flowError != null) {
      verify(authFlow).failure(eq(flowError), responseCaptor.capture());
      assertThat(responseCaptor.getValue().getStatus()).isEqualTo(httpStatusExpected);
    } else {
      verify(authFlow).success();
      verify(credentialService).invalidate(credentialModel, credentialContext);
    }
  }
}
