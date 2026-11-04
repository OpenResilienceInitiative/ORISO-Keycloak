package org.oriso.keycloak.lifecycle;
import static org.junit.Assert.*;
import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import org.junit.Test;
public class AdminAccountDeletionTest {
  private com.fasterxml.jackson.databind.JsonNode roles(String value){return parse("{\"roles\":"+value+"}").path("roles");}
  @Test public void onlyPureAdministratorRoleProfilesAreEligible(){
    AdminAccountDeletion.pure(roles("[\"restricted-agency-admin\",\"user-admin\"]"),false);
    AdminAccountDeletion.pure(roles("[\"tenant-admin\"]"),true);
    AdminAccountDeletion.pure(roles("[\"agency-admin\",\"tenant-admin\"]"),true);
  }
  @Test public void consultantIdentityAndNonAdministrativeProfilesAreAlwaysPreserved(){
    for(boolean protectedTarget:new boolean[]{false,true})
      for(String roles:new String[]{"[\"consultant\",\"tenant-admin\"]","[\"consultant\",\"group-chat-consultant\",\"restricted-agency-admin\",\"user-admin\"]","[\"user\"]","[\"group-chat-consultant\",\"tenant-admin\"]"})
        assertThrows(jakarta.ws.rs.ForbiddenException.class,()->AdminAccountDeletion.pure(roles(roles),protectedTarget));
  }
}
