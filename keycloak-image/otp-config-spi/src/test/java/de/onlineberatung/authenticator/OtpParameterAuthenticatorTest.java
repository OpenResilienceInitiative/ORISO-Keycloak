package de.onlineberatung.authenticator;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import java.util.Collections;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
//import org.keycloak.models.UserCredentialManager;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.mockito.ArgumentCaptor;

public class OtpParameterAuthenticatorTest {

  private OtpParameterAuthenticator authenticator;
  private AuthenticationFlowContext authFlow;
  private UserModel user;
  private RealmModel realm;
  private SubjectCredentialManager credentialManager;
  private HttpRequest httpRequest;
  private MultivaluedHashMap<String, String> decodedFormParams;
  private KeycloakSession session;

  @Before
  public void setUp() {
    authFlow = mock(AuthenticationFlowContext.class);
    when(authFlow.getHttpRequest()).thenReturn(mock(HttpRequest.class));
    realm = mock(RealmModel.class);
    when(authFlow.getRealm()).thenReturn(realm);
    user = mock(UserModel.class);
    when(authFlow.getUser()).thenReturn(user);
    session = mock(KeycloakSession.class);
    when(authFlow.getSession()).thenReturn(session);
    credentialManager = mock(SubjectCredentialManager.class);
    when(user.credentialManager()).thenReturn(credentialManager);
    httpRequest = mock(HttpRequest.class);
    decodedFormParams = new MultivaluedHashMap<>();
    when(httpRequest.getDecodedFormParameters()).thenReturn(decodedFormParams);
    authenticator = new OtpParameterAuthenticator();
  }

  @Test
  public void isConfigured_should_be_true_if_otp_auth_is_configured_for_user() {
    when(user.credentialManager()).thenReturn(credentialManager);
    when((credentialManager.isConfiguredFor(OTPCredentialModel.TYPE))).thenReturn(true);

    var configured = authenticator.configuredFor(session, realm, user);

    assertThat(configured).isTrue();
  }

  @Test
  public void isConfigured_should_be_false_if_otp_auth_is_not_configured_for_user() {
    var configured = authenticator.configuredFor(session, realm, user);

    assertThat(configured).isFalse();
  }

  @Test
  public void should_fail_if_request_contains_no_form_params() {
    when(authFlow.getHttpRequest()).thenReturn(httpRequest);

    authenticator.authenticate(authFlow);

    var responseCaptor = ArgumentCaptor.forClass(Response.class);
    verify(authFlow).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS),
        responseCaptor.capture());
    assertThat(responseCaptor.getValue().getStatus()).isEqualTo(400);
    var challenge = responseCaptor.getValue().readEntity(Challenge.class);
    assertThat(challenge.getOtpType()).isEqualTo(OtpType.APP);
  }

  @Test
  public void should_be_successful_if_form_params_contain_otp() {
    decodedFormParams.put("otp", Collections.singletonList("765432"));
    when(authFlow.getHttpRequest()).thenReturn(httpRequest);

    authenticator.authenticate(authFlow);
    verify(authFlow).success();
  }

  @Test
  public void should_fail_with_challenge_if_otp_param_is_blank() {
    decodedFormParams.put("otp", Collections.singletonList(" "));
    when(authFlow.getHttpRequest()).thenReturn(httpRequest);

    authenticator.authenticate(authFlow);

    var responseCaptor = ArgumentCaptor.forClass(Response.class);
    verify(authFlow).failure(eq(AuthenticationFlowError.INVALID_CREDENTIALS),
        responseCaptor.capture());
    assertThat(responseCaptor.getValue().getStatus()).isEqualTo(400);
    var challenge = responseCaptor.getValue().readEntity(Challenge.class);
    assertThat(challenge.getOtpType()).isEqualTo(OtpType.APP);
  }
}
