package de.onlineberatung.authenticator;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.ForbiddenException;
import java.util.Arrays;
import org.junit.Test;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

public class BearerTokenSessionAuthenticatorTest {

  @Test
  public void the_dedicated_otp_config_admin_role_is_accepted() {
    var caller = userWithDirectRoles("default-roles-online-beratung", "otp-config-admin");

    assertThatCode(() -> BearerTokenSessionAuthenticator.requireAllowedRole(caller))
        .doesNotThrowAnyException();
  }

  @Test
  public void the_legacy_technical_role_is_still_accepted_during_the_migration() {
    var caller = userWithDirectRoles("default-roles-online-beratung", "technical");

    assertThatCode(() -> BearerTokenSessionAuthenticator.requireAllowedRole(caller))
        .doesNotThrowAnyException();
  }

  @Test
  public void a_caller_without_an_allowed_role_is_forbidden() {
    var caller = userWithDirectRoles("default-roles-online-beratung", "tenant-admin");

    assertThatThrownBy(() -> BearerTokenSessionAuthenticator.requireAllowedRole(caller))
        .isInstanceOf(ForbiddenException.class);
  }

  @Test
  public void a_token_without_a_user_is_forbidden() {
    assertThatThrownBy(() -> BearerTokenSessionAuthenticator.requireAllowedRole(null))
        .isInstanceOf(ForbiddenException.class);
  }

  private static UserModel userWithDirectRoles(String... names) {
    var roles = Arrays.stream(names).map(BearerTokenSessionAuthenticatorTest::role).toList();
    var user = mock(UserModel.class);
    when(user.getRoleMappingsStream()).thenAnswer(invocation -> roles.stream());
    return user;
  }

  private static RoleModel role(String name) {
    var role = mock(RoleModel.class);
    when(role.getName()).thenReturn(name);
    return role;
  }
}
