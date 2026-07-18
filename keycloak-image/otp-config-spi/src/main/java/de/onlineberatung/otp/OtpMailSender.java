package de.onlineberatung.otp;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.mail.MailSendingException;

public interface OtpMailSender {

  void sendOtpCode(Otp otp,
      CredentialContext credentialContext) throws MailSendingException;

}
