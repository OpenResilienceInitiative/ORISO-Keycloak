package de.onlineberatung.log;

import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriInfo;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.common.util.StackUtil;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerTransaction;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * LoggingEventListenerProvider logs given event with logger, but omits the IP address. See also
 * {@link org.keycloak.events.log.JBossLoggingEventListenerProvider}.
 */
public class LoggingEventListenerProvider implements EventListenerProvider {

  private final KeycloakSession session;
  private final Logger logger;
  private final Logger.Level successLevel;
  private final Logger.Level errorLevel;
  private final EventListenerTransaction listenerTransaction = new EventListenerTransaction(
      this::logAdminEvent, this::logEvent);

  public LoggingEventListenerProvider(KeycloakSession session, Logger logger,
      Logger.Level successLevel, Logger.Level errorLevel) {
    this.session = session;
    this.logger = logger;
    this.successLevel = successLevel;
    this.errorLevel = errorLevel;
    this.session.getTransactionManager().enlistAfterCompletion(listenerTransaction);
  }

  @Override
  public void onEvent(Event event) {
    listenerTransaction.addEvent(event);
  }

  @Override
  public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
    listenerTransaction.addAdminEvent(adminEvent, includeRepresentation);
  }

  private void logEvent(Event event) {
    Logger.Level level = event.getError() != null ? errorLevel : successLevel;

    if (!logger.isEnabled(level)) {
      return;
    }

    StringBuilder sb = new StringBuilder();
    sb.append("type=");
    sb.append(event.getType());
    sb.append(", realmId=");
    sb.append(event.getRealmId());
    sb.append(", clientId=");
    sb.append(event.getClientId());
    sb.append(", userId=");
    sb.append(event.getUserId());

    if (event.getError() != null) {
      sb.append(", error=");
      sb.append(event.getError());
    }

    if (event.getDetails() != null) {
      appendDetails(event, sb);
    }

    AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
    if (authSession != null) {
      appendSession(sb, authSession);
    }

    if (logger.isTraceEnabled()) {
      setKeycloakContext(sb);

      if (StackUtil.isShortStackTraceEnabled()) {
        sb.append(", stackTrace=").append(StackUtil.getShortStackTrace());
      }
    }

    logger.log(logger.isTraceEnabled() ? Logger.Level.TRACE : level, sb.toString());
  }

  private void appendDetails(Event event, StringBuilder sb) {
    for (Map.Entry<String, String> e : event.getDetails().entrySet()) {
      sb.append(", ");
      sb.append(e.getKey());
      if (e.getValue() == null || e.getValue().indexOf(' ') == -1) {
        sb.append("=");
        sb.append(e.getValue());
      } else {
        sb.append("='");
        sb.append(e.getValue());
        sb.append("'");
      }
    }
  }

  private void appendSession(StringBuilder sb, AuthenticationSessionModel authSession) {
    sb.append(", authSessionParentId=");
    sb.append(authSession.getParentSession().getId());
    sb.append(", authSessionTabId=");
    sb.append(authSession.getTabId());
  }

  private void logAdminEvent(AdminEvent adminEvent, boolean includeRepresentation) {
    Logger.Level level = adminEvent.getError() != null ? errorLevel : successLevel;

    if (!logger.isEnabled(level)) {
      return;
    }

    StringBuilder sb = new StringBuilder();
    sb.append("operationType=");
    sb.append(adminEvent.getOperationType());
    sb.append(", realmId=");
    sb.append(adminEvent.getAuthDetails().getRealmId());
    sb.append(", clientId=");
    sb.append(adminEvent.getAuthDetails().getClientId());
    sb.append(", userId=");
    sb.append(adminEvent.getAuthDetails().getUserId());
    sb.append(", resourceType=");
    sb.append(adminEvent.getResourceTypeAsString());
    sb.append(", resourcePath=");
    sb.append(adminEvent.getResourcePath());

    if (adminEvent.getError() != null) {
      sb.append(", error=");
      sb.append(adminEvent.getError());
    }

    if (logger.isTraceEnabled()) {
      setKeycloakContext(sb);
    }

    logger.log(logger.isTraceEnabled() ? Logger.Level.TRACE : level, sb.toString());
  }

  @Override
  public void close() {
    // unused
  }

  private void setKeycloakContext(StringBuilder sb) {
    KeycloakContext context = session.getContext();
    UriInfo uriInfo = context.getUri();
    HttpHeaders headers = context.getRequestHeaders();
    if (uriInfo != null) {
      sb.append(", requestUri=");
      sb.append(uriInfo.getRequestUri().toString());
    }

    if (headers == null) {
      return;
    }

    sb.append(", cookies=[");
    boolean isFirst = true;
    for (Map.Entry<String, Cookie> cookieEntry : headers.getCookies().entrySet()) {
      if (isFirst) {
        isFirst = false;
      } else {
        sb.append(", ");
      }
      sb.append(cookieEntry.getValue());
    }
    sb.append("]");
  }

}
