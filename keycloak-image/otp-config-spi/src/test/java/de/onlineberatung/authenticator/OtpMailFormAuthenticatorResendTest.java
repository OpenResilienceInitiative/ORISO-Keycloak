package de.onlineberatung.authenticator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;

/**
 * The browser login (Matrix/Element SSO, account console) mails codes from the same credential as
 * the app login. Without the same brake here, reloading the code page would be the way around the
 * cooldown and the cap (#1338).
 */
public class OtpMailFormAuthenticatorResendTest {

  private MailOtpLoginFixture fx;
  private OtpMailFormAuthenticator authenticator;

  @Before
  public void setUp() {
    fx = new MailOtpLoginFixture();
    authenticator = new OtpMailFormAuthenticator(fx.otpService, fx.credentialService,
        fx.mailSender, fx.defaultThrottle());
  }

  @Test
  public void reloading_the_code_page_within_the_cooldown_mails_nothing_and_keeps_the_code() {
    var first = openCodePage();
    assertThat(fx.mailedCodes).hasSize(1);
    verify(first).challenge(any(Response.class));
    var code = fx.lastMailedCode();

    fx.clock.advanceSeconds(10);
    var reload = openCodePage();

    assertThat(fx.mailedCodes).hasSize(1);
    verify(reload).challenge(any(Response.class));
    verify(submitCode(code)).success();
  }

  @Test
  public void the_code_page_mails_a_new_code_after_the_cooldown() {
    openCodePage();
    fx.clock.advanceSeconds(30);

    openCodePage();

    assertThat(fx.mailedCodes).hasSize(2);
  }

  @Test
  public void the_code_page_stops_mailing_once_the_cap_is_reached() {
    for (int i = 0; i < 5; i++) {
      openCodePage();
      fx.clock.advanceSeconds(31);
    }

    var refused = openCodePage();

    assertThat(fx.mailedCodes).hasSize(5);
    verify(refused).failure(eq(AuthenticationFlowError.ACCESS_DENIED), any(Response.class));
    verify(refused, never()).challenge(any(Response.class));
  }

  private AuthenticationFlowContext openCodePage() {
    var flow = flow(new MultivaluedHashMap<>());
    authenticator.authenticate(flow);
    return flow;
  }

  private AuthenticationFlowContext submitCode(String code) {
    var params = new MultivaluedHashMap<String, String>();
    params.putSingle("otp", code);
    var flow = flow(params);
    authenticator.action(flow);
    return flow;
  }

  private AuthenticationFlowContext flow(MultivaluedHashMap<String, String> params) {
    var flow = mock(AuthenticationFlowContext.class);
    var httpRequest = mock(HttpRequest.class);
    when(flow.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getDecodedFormParameters()).thenReturn(params);
    when(flow.getSession()).thenReturn(fx.session);
    when(flow.getRealm()).thenReturn(fx.realm);
    when(flow.getUser()).thenReturn(fx.user);
    var form = mock(LoginFormsProvider.class);
    when(flow.form()).thenReturn(form);
    when(form.setError(anyString())).thenReturn(form);
    when(form.createLoginTotp()).thenReturn(mock(Response.class));
    return flow;
  }
}
