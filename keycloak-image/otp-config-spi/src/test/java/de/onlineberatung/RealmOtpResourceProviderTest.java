package de.onlineberatung;

import de.onlineberatung.authenticator.SessionAuthenticator;
import de.onlineberatung.credential.AppOtpCredentialService;
import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpInfoDTO;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpSetupDTO;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.SuccessWithEmail;
import de.onlineberatung.mail.MailSendingException;
import de.onlineberatung.otp.Otp;
import de.onlineberatung.otp.OtpMailSender;
import de.onlineberatung.otp.OtpService;
import de.onlineberatung.otp.ValidationResult;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import org.mockito.Mockito;

import java.time.Clock;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class RealmOtpResourceProviderTest {

  private OtpService otpService;
  private OtpMailSender mailSender;
  private RealmOtpResourceProvider resourceProvider;
  private UserModel user;
  private UserProvider userProvider;
  private RealmModel realm;
  private MailOtpCredentialService mailCredentialService;
  private CredentialContext credentialContext;
  private AppOtpCredentialService appCredentialService;

  @Before
  public void setUp() {
    KeycloakSession session = mock(KeycloakSession.class);
    otpService = mock(OtpService.class);
    mailCredentialService = mock(MailOtpCredentialService.class);
    mailSender = mock(OtpMailSender.class);
    var sessionAuthenticator = mock(SessionAuthenticator.class);
    var keycloakContext = mock(KeycloakContext.class);
    when(session.getContext()).thenReturn(keycloakContext);
    realm = mock(RealmModel.class);
    when(keycloakContext.getRealm()).thenReturn(realm);
    userProvider = mock(UserProvider.class);
    when(session.users()).thenReturn(userProvider);
    user = mock(UserModel.class);
    credentialContext = new CredentialContext(session, realm, user);
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    appCredentialService = mock(AppOtpCredentialService.class);
    resourceProvider = new RealmOtpResourceProvider(session, otpService, mailSender,
        sessionAuthenticator, appCredentialService, mailCredentialService);
  }

  @Test
  public void sendVerificationMail_should_create_and_send_otp() {
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");
    var otp = new Otp("123", 450L, 1234567L, "hk@test.de", 0);
    when(otpService.createOtp("hk@test.de")).thenReturn(otp);

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(200);
    verify(mailSender).sendOtpCode(otp, credentialContext);
  }

  @Test
  public void sendVerificationMail_should_update_and_send_credentials_if_mail_was_already_send_but_not_verified_yet() {
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    var oldOtp = new Otp("1223", 1L, 2L, "hk@test.de", 0);
    var notYetActivatedCredentials = MailOtpCredentialModel.createOtpModel(oldOtp,
        Clock.systemDefaultZone(), false);
    when(mailCredentialService.getCredential(credentialContext)).thenReturn(
        notYetActivatedCredentials);
    var newOtp = new Otp("667722", 1L, 3L, "hk@test.de", 0);
    when(otpService.createOtp("hk@test.de")).thenReturn(newOtp);

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(200);
    var expectedCredentials = notYetActivatedCredentials.updateFrom(newOtp);
    verify(mailSender).sendOtpCode(newOtp, credentialContext);
    verify(mailCredentialService).update(expectedCredentials, credentialContext);
  }

  @Test
  public void sendVerificationMail_should_be_bad_request_if_user_not_found() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(null);
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(400);
  }

  @Test
  public void sendVerificationMail_should_be_bad_request_if_no_email_given() {
    var mailSetup = new OtpSetupDTO();
    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(400);
  }

  @Test
  public void sendVerificationMail_should_invalidate_otp_if_sending_fails() {
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");
    var otp = new Otp("123", 450L, 1234567L, "hk@test.de", 0);
    when(otpService.createOtp("hk@test.de")).thenReturn(otp);
    Mockito.doThrow(MailSendingException.class).when(mailSender).sendOtpCode(any(), any());
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, Clock.systemDefaultZone());
    when(mailCredentialService.createCredential(otp, credentialContext)).thenReturn(
        credentialModel);

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(500);
    verify(mailCredentialService).invalidate(credentialModel, credentialContext);
  }

  @Test
  public void sendVerification_should_return_conflict_if_credentials_are_already_activated() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("test@test.de");
    var otp = new Otp("1223", 1L, 2L, "hk@test.de", 0);
    var activatedCredentials = MailOtpCredentialModel.createOtpModel(otp, Clock.systemDefaultZone(),
        true);
    when(mailCredentialService.getCredential(credentialContext)).thenReturn(activatedCredentials);
    when(mailCredentialService.createCredential(otp, credentialContext)).thenReturn(
        activatedCredentials);

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(409);
  }

  @Test
  public void sendVerification_should_be_ok_if_2fa_via_app_is_already_configured() {
    var mailSetup = new OtpSetupDTO();
    mailSetup.setEmail("hk@test.de");
    var otp = new Otp("123", 450L, 1234567L, "hk@test.de", 0);
    when(otpService.createOtp("hk@test.de")).thenReturn(otp);

    var response = resourceProvider.sendVerificationMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(200);
    verify(mailSender).sendOtpCode(otp, credentialContext);
  }

  @Test
  public void setupOtpMail_should_be_bad_request_if_user_not_found() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(null);
    var mailSetup = new OtpSetupDTO();

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(400);
    verify(appCredentialService, never()).deleteCredentials(any(CredentialContext.class));
  }

  @Test
  public void setupOtpMail_should_send_email_address_as_response_upon_successful_otp_creation() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    var mailSetup = new OtpSetupDTO();
    mailSetup.setInitialCode("1223");
    var otp = new Otp("1223", 1L, 2L, "hk@test.de", 0);
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, Clock.systemDefaultZone());
    when(otpService.validate("1223", otp)).thenReturn(
        ValidationResult.VALID);
    when(mailCredentialService.getCredential(credentialContext)).thenReturn(credentialModel);
    when(mailCredentialService.createCredential(otp, credentialContext)).thenReturn(
        credentialModel);

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(201);
    var otpWithEmailSuccess = response.readEntity(SuccessWithEmail.class);
    assertThat(otpWithEmailSuccess.getEmail()).isEqualTo("hk@test.de");
    verify(mailCredentialService).activate(credentialModel, credentialContext);
    verify(appCredentialService).deleteCredentials(any(CredentialContext.class));
  }

  @Test
  public void setupOtpMail_should_return_bad_request_if_no_credentials_exist() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    var mailSetup = new OtpSetupDTO();
    mailSetup.setInitialCode("1223");

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(400);
    verify(appCredentialService, never()).deleteCredentials(any(CredentialContext.class));
  }

  @Test
  public void setupOtpMail_should_return_ok_and_delete_app_if_already_configured_for_user() {
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    var mailSetup = new OtpSetupDTO();
    mailSetup.setInitialCode("1223");
    var otp = new Otp("1223", 1L, 2L, "hk@test.de", 0);
    var activatedCredentials = MailOtpCredentialModel.createOtpModel(otp, Clock.systemDefaultZone(),
        true);
    when(mailCredentialService.getCredential(credentialContext)).thenReturn(activatedCredentials);
    when(mailCredentialService.createCredential(otp, credentialContext)).thenReturn(
        activatedCredentials);

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(200);
    verify(appCredentialService).deleteCredentials(any(CredentialContext.class));
  }

  @Test
  public void setupOtpMail_should_be_created_and_delete_app_if_2fa_via_app_is_already_configured() {
    var mailSetup = new OtpSetupDTO();
    mailSetup.setInitialCode("1223");
    when(userProvider.getUserByUsername(realm, "heinrich")).thenReturn(user);
    var otp = new Otp("1223", 1L, 2L, "hk@test.de", 0);
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, Clock.systemDefaultZone());
    when(otpService.validate("1223", otp)).thenReturn(
        ValidationResult.VALID);
    when(mailCredentialService.getCredential(credentialContext)).thenReturn(credentialModel);
    when(mailCredentialService.createCredential(otp, credentialContext)).thenReturn(
        credentialModel);

    var response = resourceProvider.setupOtpMail("heinrich", mailSetup);

    assertThat(response.getStatus()).isEqualTo(201);
    verify(appCredentialService).deleteCredentials(any(CredentialContext.class));
  }

  @Test
  public void getOtpSetupInfo_should_return_type_app_if_app_2fa_is_configured() {
    when(appCredentialService.is2FAConfigured(credentialContext)).thenReturn(true);

    var response = resourceProvider.getOtpSetupInfo("heinrich");

    assertThat(response.getStatus()).isEqualTo(200);
    var otpInfo = response.readEntity(OtpInfoDTO.class);
    assertThat(otpInfo.getOtpSetup()).isTrue();
    assertThat(otpInfo.getOtpType()).isEqualTo(OtpType.APP);
    assertThat(otpInfo.getOtpSecret()).isNull();
    assertThat(otpInfo.getOtpSecretQrCode()).isNull();
  }

  @Test
  public void getOtpSetupInfo_should_return_type_mail_if_mail_2fa_is_configured() {
    when(appCredentialService.generateSecret()).thenReturn("someSecret");
    when(appCredentialService.generateQRCodeBase64("someSecret", credentialContext)).thenReturn(
        "base64EncodedQRCode");
    when(mailCredentialService.is2FAConfigured(credentialContext)).thenReturn(true);

    var response = resourceProvider.getOtpSetupInfo("heinrich");

    assertThat(response.getStatus()).isEqualTo(200);
    var otpInfo = response.readEntity(OtpInfoDTO.class);
    assertThat(otpInfo.getOtpSetup()).isTrue();
    assertThat(otpInfo.getOtpType()).isEqualTo(OtpType.EMAIL);
    assertThat(otpInfo.getOtpSecret()).isEqualTo("someSecret");
    assertThat(otpInfo.getOtpSecretQrCode()).isEqualTo("base64EncodedQRCode");
  }

  @Test
  public void getOtpSetupInfo_should_return_secret_and_qr_code_for_setting_up_app_otp_if_none_2fa_configured() {
    when(appCredentialService.generateSecret()).thenReturn("someSecret");
    when(appCredentialService.generateQRCodeBase64("someSecret", credentialContext)).thenReturn(
        "base64EncodedQRCode");

    var response = resourceProvider.getOtpSetupInfo("heinrich");

    assertThat(response.getStatus()).isEqualTo(200);
    var expectedOtpInfo = new OtpInfoDTO();
    expectedOtpInfo.setOtpSetup(false);
    expectedOtpInfo.setOtpSecret("someSecret");
    expectedOtpInfo.setOtpSecretQrCode("base64EncodedQRCode");
    var otpInfo = response.readEntity(OtpInfoDTO.class);
    assertThat(expectedOtpInfo).isEqualTo(otpInfo);
  }

  @Test
  public void setupOtp_should_be_created_and_delete_mail_otp_if_mail_otp_is_already_configured() {
    var otpSetup = new OtpSetupDTO();
    otpSetup.setSecret("secretSecret");
    otpSetup.setInitialCode("4711");
    var credentialModel = mock(OTPCredentialModel.class);
    when(appCredentialService.createModel("secretSecret", credentialContext)).thenReturn(
        credentialModel);
    when((appCredentialService.validate("4711", credentialModel, credentialContext))).thenReturn(
        true);

    var response = resourceProvider.setupOtp("heinrich", otpSetup);

    assertThat(response.getStatus()).isEqualTo(201);
    verify(mailCredentialService).deleteCredential(any(CredentialContext.class));
  }


  @Test
  public void setupOtp_should_be_ok_if_app_otp_is_already_configured() {
    when(appCredentialService.is2FAConfigured(credentialContext)).thenReturn(true);

    var response = resourceProvider.setupOtp("heinrich", new OtpSetupDTO());

    assertThat(response.getStatus()).isEqualTo(200);
  }

  @Test
  public void setupOtp_should_create_credentials_after_successful_validation() {
    var otpSetup = new OtpSetupDTO();
    otpSetup.setSecret("secretSecret");
    otpSetup.setInitialCode("4711");
    var credentialModel = mock(OTPCredentialModel.class);
    when(appCredentialService.createModel("secretSecret", credentialContext)).thenReturn(
        credentialModel);
    when((appCredentialService.validate("4711", credentialModel, credentialContext))).thenReturn(
        true);

    var response = resourceProvider.setupOtp("heinrich", otpSetup);

    assertThat(response.getStatus()).isEqualTo(201);
    verify(appCredentialService).createCredential("4711", credentialModel, credentialContext);
  }

  @Test
  public void setupOtp_should_be_unauthorized_if_validation_fails() {
    var otpSetup = new OtpSetupDTO();
    otpSetup.setSecret("secretSecret");
    otpSetup.setInitialCode("4711");
    var credentialModel = mock(OTPCredentialModel.class);
    when(appCredentialService.createModel("secretSecret", credentialContext)).thenReturn(
        credentialModel);
    when((appCredentialService.validate("4711", credentialModel, credentialContext))).thenReturn(
        false);

    var response = resourceProvider.setupOtp("heinrich", otpSetup);

    assertThat(response.getStatus()).isEqualTo(401);
  }

  @Test
  public void deleteOtp_should_delete_all_otps() {
    var response = resourceProvider.deleteOtp("heinrich");

    assertThat(response.getStatus()).isEqualTo(200);
    verify(appCredentialService).deleteCredentials(credentialContext);
    verify(mailCredentialService).deleteCredential(credentialContext);
  }
}
