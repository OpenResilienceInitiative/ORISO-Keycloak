package de.onlineberatung.mail;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.otp.Otp;
import de.onlineberatung.otp.OtpMailSender;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.email.freemarker.FreeMarkerEmailTemplateProvider;
import org.keycloak.models.UserModel;

import java.util.HashMap;

import static java.util.Collections.emptyList;

public class DefaultMailSender implements OtpMailSender {

  private static final int MINUTE_IN_SECONDS = 60;
  private static final String OTP_MAIL_TEMPLATE = "otp-email.ftl";
  private static final String EMAIL_SUBJECT = "emailSubject";
  private static final String OTP_ATTRIBUTE = "otp";
  private static final String TTL_ATTRIBUTE = "ttl";

  @Override
  public void sendOtpCode(Otp otp, CredentialContext context) throws MailSendingException {
    try {
      var mailRecipient = createMailRecipient(otp, context);
      var mailAttributes = createMailAttributes(otp);
      var mailTemplateProvider = createMailTemplateProvider(context, mailRecipient);

      mailTemplateProvider.send(EMAIL_SUBJECT, emptyList(), OTP_MAIL_TEMPLATE, mailAttributes);
    } catch (Exception e) {
      throw new MailSendingException("failed to send otp mail", e);
    }
  }

  private UserModel createMailRecipient(Otp otp, CredentialContext context) {
    var mailRecipient = context.getUser();
    mailRecipient.setEmail(otp.getEmail());

    return mailRecipient;
  }

  private HashMap<String, Object> createMailAttributes(Otp otp) {
    var attributes = new HashMap<String, Object>();
    attributes.put(OTP_ATTRIBUTE, otp.getCode());
    var ttlInSeconds = otp.getTtlInSeconds() > 0 ? otp.getTtlInSeconds() : 60;
    attributes.put(TTL_ATTRIBUTE, Math.floorDiv(ttlInSeconds, MINUTE_IN_SECONDS));
    return attributes;
  }

  private EmailTemplateProvider createMailTemplateProvider(CredentialContext context,
      UserModel mailRecipient) {
    var emailTemplateProvider = new FreeMarkerEmailTemplateProvider(context.getSession());
    emailTemplateProvider.setRealm(context.getRealm());
    emailTemplateProvider.setUser(mailRecipient);
    return emailTemplateProvider;
  }
}

