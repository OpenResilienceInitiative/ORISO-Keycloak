package org.oriso.keycloak.lifecycle;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;

/** Only an already checked Magic Link can omit the ordinary username/password subflow. */
public final class MagicLinkPasswordCondition extends MagicLinkFlow implements ConditionalAuthenticator {
  public String getId() { return "oriso-magic-link-ordinary-password"; }
  public String getDisplayType() { return "ORISO ordinary password condition"; }
  public boolean matchCondition(AuthenticationFlowContext context) {
    return !MagicLinkAuthority.present(context) || context.getAuthenticationSession().getAuthNote(MagicLinkAuthority.NOTE) == null;
  }
  public void authenticate(AuthenticationFlowContext context) { context.success(); }
}
