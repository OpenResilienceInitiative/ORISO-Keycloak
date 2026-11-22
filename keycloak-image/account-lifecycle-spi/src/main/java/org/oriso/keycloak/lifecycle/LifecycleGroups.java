package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.persistence.LockModeType;
import java.util.*;
import java.util.stream.Collectors;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.*;
import org.keycloak.models.jpa.GroupAdapter;
import org.keycloak.models.jpa.entities.GroupEntity;
import org.keycloak.models.jpa.entities.RoleEntity;

final class LifecycleGroups {
  static final Set<String> KNOWN =
      Set.of(
          "user", "consultant", "group-chat-consultant", "restricted-agency-admin", "user-admin");

  static String allowedKind(Set<String> roles) {
    if (roles.equals(Set.of("user"))) return "ASKER";
    Set<String> consultant = Set.of("consultant"),
        fullConsultant = Set.of("consultant", "group-chat-consultant");
    if (roles.equals(consultant) || roles.equals(fullConsultant)) return "CONSULTANT";
    if (roles.equals(Set.of("restricted-agency-admin", "user-admin"))) return "AGENCY_ADMIN";
    if (roles.equals(Set.of("consultant", "restricted-agency-admin", "user-admin"))
        || roles.equals(
            Set.of("consultant", "group-chat-consultant", "restricted-agency-admin", "user-admin")))
      return "CONSULTANT_AGENCY_ADMIN";
    return null;
  }

  static void scope(JsonNode scope) {
    fields(scope, "tenantId", "registrationKind", "initialGroup", "origin");
    String tenant = text(scope, "tenantId", 40, true),
        kind = text(scope, "registrationKind", 30, false);
    if (tenant != null && !tenant.matches("[1-9][0-9]{0,18}")) deny();
    if (!Set.of("ASKER", "ANONYMOUS", "CONSULTANT", "AGENCY_ADMIN", "CONSULTANT_AGENCY_ADMIN")
        .contains(kind)) deny();
    if (tenant == null && !Set.of("ASKER", "ANONYMOUS").contains(kind)) deny();
    text(scope, "initialGroup", 512, false);
    var origin = scope.path("origin");
    fields(
        origin,
        "kind",
        "workflowId",
        "provenance",
        "humanIssuer",
        "humanSubject",
        "humanAuthority",
        "agencyIds");
    String source = text(origin, "kind", 30, false);
    if (!Set.of("REGISTRATION", "ANONYMOUS", "INVITATION", "HUMAN_ADMIN", "IMPORT")
        .contains(source)) deny();
    text(origin, "workflowId", 255, false);
    text(origin, "provenance", 512, false);
    String issuer = text(origin, "humanIssuer", 512, true),
        subject = text(origin, "humanSubject", 255, true),
        authority = text(origin, "humanAuthority", 255, true);
    if ("HUMAN_ADMIN".equals(source) && (issuer == null || subject == null || authority == null))
      deny();
    if ((issuer == null || subject == null || authority == null)
        && !(issuer == null && subject == null && authority == null)) deny();
    if ("REGISTRATION".equals(source) && !"ASKER".equals(kind)
        || "ANONYMOUS".equals(source) && !"ANONYMOUS".equals(kind)
        || "IMPORT".equals(source) && !"CONSULTANT".equals(kind)) deny();
    var agencies = origin.path("agencyIds");
    if (!agencies.isArray() || agencies.size() > 100) bad();
    String previous = null;
    for (var agency : agencies) {
      if (!agency.isTextual()
          || !agency.asText().matches("[1-9][0-9]{0,18}")
          || previous != null && previous.compareTo(agency.asText()) >= 0) deny();
      previous = agency.asText();
    }
  }

  static GroupModel group(RealmModel realm, String path, Set<String> expected) {
    if (expected == null) deny();
    var roots =
        realm.getTopLevelGroupsStream().filter(g -> "human-roles".equals(g.getName())).toList();
    if (roots.size() != 1 || roots.get(0).getRoleMappingsStream().findAny().isPresent()) deny();
    var found =
        roots
            .get(0)
            .getSubGroupsStream()
            .filter(g -> path.equals("/human-roles/" + g.getName()))
            .toList();
    if (found.size() != 1) deny();
    var group = found.get(0);
    var roles = group.getRoleMappingsStream().toList();
    if (group.getSubGroupsStream().findAny().isPresent()
        || roles.stream().anyMatch(r -> r.isClientRole() || r.isComposite())
        || !roles.stream().map(RoleModel::getName).collect(Collectors.toSet()).equals(expected))
      deny();
    return group;
  }

  static GroupModel pending(RealmModel realm) {
    var groups =
        realm
            .getTopLevelGroupsStream()
            .filter(g -> "pending-provisioning".equals(g.getName()))
            .toList();
    if (groups.size() != 1
        || groups.get(0).getRoleMappingsStream().findAny().isPresent()
        || groups.get(0).getSubGroupsStream().findAny().isPresent()) deny();
    return groups.get(0);
  }

  static GroupModel group(
      KeycloakSession session, RealmModel realm, String path, Set<String> expected) {
    var chosen = group(realm, path, expected);
    var parent = chosen.getParent();
    if (parent == null) deny();
    lock(session, realm, parent, Set.of(), null, false);
    return lock(session, realm, chosen, expected, parent.getId(), true);
  }

  static GroupModel pending(KeycloakSession session, RealmModel realm) {
    return lock(session, realm, pending(realm), Set.of(), null, true);
  }

  private static GroupModel lock(
      KeycloakSession session,
      RealmModel realm,
      GroupModel chosen,
      Set<String> expected,
      String parent,
      boolean leaf) {
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var stored = em.find(GroupEntity.class, chosen.getId(), LockModeType.PESSIMISTIC_WRITE);
    if (stored == null) deny();
    em.refresh(stored);
    if (!realm.getId().equals(stored.getRealm())
        || !chosen.getName().equals(stored.getName())
        || !Objects.equals(
            parent == null ? GroupEntity.TOP_PARENT_ID : parent, stored.getParentId())
        || stored.getOrganization() != null
        || stored.getType() != GroupModel.Type.REALM.intValue()) deny();
    // Scalar locks avoid managed mapping entities across Keycloak bulk deletes.
    // Lock the parent group as well: native mapping inserts must serialize even
    // when this empty pending/root group currently has no mapping rows.
    var identifiers =
        em.createNativeQuery(
                "select ROLE_ID from GROUP_ROLE_MAPPING where GROUP_ID = :id for update")
            .setParameter("id", stored.getId())
            .getResultList();
    var names = new TreeSet<String>();
    var sortedIds = new TreeSet<String>();
    for (var identifier : identifiers) sortedIds.add((String) identifier);
    for (String id : sortedIds) {
      var role = em.find(RoleEntity.class, id, LockModeType.PESSIMISTIC_WRITE);
      if (role == null) deny();
      em.refresh(role);
      if (role.isClientRole()
          || !realm.getId().equals(role.getRealmId())
          || !names.add(role.getName())
          || !em.createNativeQuery(
                  "select CHILD_ROLE from COMPOSITE_ROLE where COMPOSITE = :id for update")
              .setParameter("id", id)
              .getResultList()
              .isEmpty()) deny();
    }
    if (names.size() != identifiers.size() || !names.equals(expected)) deny();
    if (leaf
        && !em.createNativeQuery(
                "select ID from KEYCLOAK_GROUP where PARENT_GROUP = :id for update")
            .setParameter("id", stored.getId())
            .getResultList()
            .isEmpty()) deny();
    return new GroupAdapter(session, realm, em, stored);
  }

  private LifecycleGroups() {}
}
