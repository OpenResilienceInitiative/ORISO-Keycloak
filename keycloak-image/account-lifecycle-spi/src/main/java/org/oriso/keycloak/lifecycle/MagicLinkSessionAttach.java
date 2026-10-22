package org.oriso.keycloak.lifecycle;

import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.UUID;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationManager;

/** Final execution after existing MFA; native Grant/TokenManager still generate the tokens. */
public final class MagicLinkSessionAttach extends MagicLinkFlow {
  public String getId() { return "oriso-claimed-magic-link-attach"; }
  public String getDisplayType() { return "ORISO claimed Magic Link native attach"; }
  public void authenticate(AuthenticationFlowContext context) {
    if (!MagicLinkAuthority.present(context)) { context.success(); return; }
    try {
      if (authority == null) LifecycleJson.deny();
      var checked = authority.check(context);
      if (!LifecycleJson.canonical(checked.command()).equals(context.getAuthenticationSession().getAuthNote(MagicLinkAuthority.NOTE))
          || context.getUser() == null || !checked.target().equals(context.getUser().getId())
          || context.getUser().getRequiredActionsStream().findAny().isPresent()
          || !context.getAuthenticationSession().getRequiredActions().isEmpty()) LifecycleJson.deny();
      var session = context.getSession();
      var realm = context.getRealm();
      var em = CurrentNativeHumanIdentity.entityManager(session);
      String id = realm.getId()+":"+checked.workflow();
      var row = em.find(MagicLinkSession.class,id,LockModeType.PESSIMISTIC_WRITE);
      if (row != null) em.refresh(row,LockModeType.PESSIMISTIC_WRITE);
      authority.recheckMachine(context,checked);
      UserSessionModel nativeSession;
      if (row == null) {
        row = new MagicLinkSession(); row.id=id; row.realmId=realm.getId(); row.workflow=checked.workflow();
        row.target=checked.target(); row.client="app"; row.digest=checked.digest(); row.expiry=checked.expiry();
        row.ownerClient=checked.ownerClient(); row.ownerSubject=checked.ownerSubject();
        row.sessionId=UUID.randomUUID().toString();
        em.persist(row);
        // The primary key serializes a concurrent workflow before any native session is created.
        em.flush();
        nativeSession = session.sessions().createUserSession(row.sessionId,realm,checked.user(),checked.user().getUsername(),
            context.getConnection().getRemoteAddr(),"openid-connect",false,null,null,UserSessionModel.SessionPersistenceState.PERSISTENT);
        nativeSession.setState(UserSessionModel.State.LOGGED_IN);
        nativeSession.setNote("oriso.magic-link.workflow",row.workflow);
        nativeSession.setNote("oriso.magic-link.command",row.digest);
        nativeSession.setNote("oriso.magic-link.expiry",Long.toString(row.expiry));
      } else {
        if (!realm.getId().equals(row.realmId) || !checked.workflow().equals(row.workflow)
            || !checked.target().equals(row.target) || !"app".equals(row.client)
            || !checked.ownerClient().equals(row.ownerClient) || !checked.ownerSubject().equals(row.ownerSubject)
            || !checked.digest().equals(row.digest) || checked.expiry()!=row.expiry || row.expiry<=Instant.now().getEpochSecond()) LifecycleJson.deny();
        nativeSession = session.sessions().getUserSession(realm,row.sessionId);
        if (nativeSession == null || !AuthenticationManager.isSessionValid(realm,nativeSession)
            || nativeSession.getState()!=UserSessionModel.State.LOGGED_IN || !checked.target().equals(nativeSession.getUser().getId())
            || !row.workflow.equals(nativeSession.getNote("oriso.magic-link.workflow"))
            || !row.digest.equals(nativeSession.getNote("oriso.magic-link.command"))
            || !Long.toString(row.expiry).equals(nativeSession.getNote("oriso.magic-link.expiry"))) LifecycleJson.deny();
      }
      if (row.expiry<=Instant.now().getEpochSecond() || nativeSession == null || !row.sessionId.equals(nativeSession.getId())) LifecycleJson.deny();
      session.getContext().setUserSession(nativeSession);
      context.attachUserSession(nativeSession);
      context.success();
    } catch (RuntimeException failure) {
      refuse(context,failure);
    }
  }
}
