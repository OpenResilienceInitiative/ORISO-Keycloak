package org.oriso.keycloak.lifecycle;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.directgrant.ValidateUsername;

/** Selects only the proof-bound current native target; the existing OTP flow still follows. */
public final class MagicLinkAuthenticator extends MagicLinkFlow {
  public static final String ID = "oriso-claimed-magic-link";
  public static final String COMMAND = "oriso_magic_command";
  public String getId() { return ID; }
  public String getDisplayType() { return "ORISO claimed Magic Link"; }
  public void authenticate(AuthenticationFlowContext context) {
    if (!MagicLinkAuthority.present(context)) { context.success(); return; }
    try {
      if (authority == null) LifecycleJson.deny();
      var checked = authority.check(context);
      var form = context.getHttpRequest().getDecodedFormParameters();
      form.putSingle("username",checked.user().getUsername());
      try { new ValidateUsername().authenticate(context); }
      finally { form.remove("username"); }
      if (context.getUser() == null || !checked.target().equals(context.getUser().getId())) LifecycleJson.deny();
      context.getAuthenticationSession().setAuthNote(MagicLinkAuthority.NOTE,LifecycleJson.canonical(checked.command()));
    } catch (RuntimeException failure) {
      refuse(context,failure);
    }
  }
}
