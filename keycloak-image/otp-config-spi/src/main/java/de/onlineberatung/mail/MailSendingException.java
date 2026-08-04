package de.onlineberatung.mail;

public class MailSendingException extends RuntimeException {

  public MailSendingException(String message, Throwable cause) {
    super(message, cause);
  }
}
