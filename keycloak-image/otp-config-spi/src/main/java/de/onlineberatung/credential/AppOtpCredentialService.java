package de.onlineberatung.credential;

import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.utils.CredentialValidation;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.TotpUtils;

public class AppOtpCredentialService {

  private static final int KEY_LENGTH = 32;

  public OTPCredentialModel createModel(String otpSecret, CredentialContext context) {
    return OTPCredentialModel.createFromPolicy(context.getRealm(), otpSecret);
  }

  public void createCredential(String otp, OTPCredentialModel credentialModel,
      CredentialContext context) {
    CredentialHelper.createOTPCredential(context.getSession(), context.getRealm(),
        context.getUser(), otp, credentialModel);
  }

  public String generateQRCodeBase64(String otpSecret, CredentialContext context) {
    return TotpUtils.qrCode(otpSecret, context.getRealm(), context.getUser());
  }

  public String generateSecret() {
    return HmacOTP.generateSecret(KEY_LENGTH);
  }

  public boolean is2FAConfigured(CredentialContext context) {
    return context.getUser().credentialManager().isConfiguredFor(OTPCredentialModel.TYPE);
  }

  public boolean validate(String otp, OTPCredentialModel credentialModel,
      CredentialContext context) {
    return CredentialValidation.validOTP(otp, credentialModel,
        context.getRealm().getOTPPolicy().getLookAheadWindow());
  }

  public void deleteCredentials(CredentialContext context) {
    var userCredentialManager = context.getUser().credentialManager();
    var credentials = userCredentialManager.getStoredCredentialsByTypeStream(
        OTPCredentialModel.TYPE);
    // CredentialHelper.deleteOTPCredential was removed after Keycloak 22
    credentials.forEach(
        credentialModel -> userCredentialManager.removeStoredCredentialById(
            credentialModel.getId()));
  }
}
