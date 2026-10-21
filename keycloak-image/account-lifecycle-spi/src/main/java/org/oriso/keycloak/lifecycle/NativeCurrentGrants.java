package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.deny;

import jakarta.persistence.EntityManager;
import java.util.*;
import org.keycloak.models.jpa.entities.GroupEntity;

/** Current scalar locking projection; never authorizes from cached model getters. */
final class NativeCurrentGrants {
  record Group(String id, String name, String parentId) {}
  record Grants(Set<String> realmRoles, Map<String, Set<String>> clientRoles,
      Map<String, Group> groups, Map<String, String> paths) {}

  static Grants read(EntityManager em, String realmId, Set<String> directRoles, Set<String> directGroups) {
    var groupRows = new TreeMap<String, Group>();
    var pendingGroups = new TreeSet<>(directGroups);
    var roleIds = new TreeSet<>(directRoles);
    while (!pendingGroups.isEmpty()) {
      String id = pendingGroups.pollFirst();
      if (groupRows.containsKey(id)) continue;
      if (groupRows.size() >= 100) deny();
      var row = one(em, "select ID, NAME, PARENT_GROUP, REALM_ID, TYPE, ORG_ID from KEYCLOAK_GROUP where ID = :id for update", id);
      if (!realmId.equals(text(row[3])) || !Integer.valueOf(0).equals(((Number) row[4]).intValue())
          || row[5] != null || row[1] == null || text(row[1]).contains("/")) deny();
      String parent = text(row[2]);
      if (GroupEntity.TOP_PARENT_ID.equals(parent)) parent = null;
      groupRows.put(id, new Group(id, text(row[1]), parent));
      if (parent != null) pendingGroups.add(parent);
      roleIds.addAll(ids(em, "select ROLE_ID from GROUP_ROLE_MAPPING where GROUP_ID = :id order by ROLE_ID for update", id));
    }
    var paths = new TreeMap<String, String>();
    for (String id : groupRows.keySet()) path(id, groupRows, paths, new HashSet<>());
    var realmRoles = new TreeSet<String>();
    var clientRoles = new TreeMap<String, Set<String>>();
    var visitedRoles = new HashSet<String>();
    while (!roleIds.isEmpty()) {
      String id = roleIds.pollFirst();
      if (!visitedRoles.add(id)) continue;
      if (visitedRoles.size() > 1000) deny();
      var row = one(em, "select ID, NAME, REALM_ID, CLIENT_ROLE, CLIENT from KEYCLOAK_ROLE where ID = :id for update", id);
      String name = text(row[1]);
      if (name == null || name.isBlank()) deny();
      if (flag(row[3])) {
        if (row[4] == null) deny();
        var client = one(em, "select CLIENT_ID, REALM_ID, ENABLED from CLIENT where ID = :id for update", text(row[4]));
        if (!realmId.equals(text(client[1])) || !flag(client[2])) deny();
        clientRoles.computeIfAbsent(text(client[0]), ignored -> new TreeSet<>()).add(name);
      } else {
        if (!realmId.equals(text(row[2])) || row[4] != null) deny();
        realmRoles.add(name);
      }
      roleIds.addAll(ids(em, "select CHILD_ROLE from COMPOSITE_ROLE where COMPOSITE = :id order by CHILD_ROLE for update", id));
    }
    var immutableClients = new TreeMap<String, Set<String>>();
    clientRoles.forEach((id, roles) -> immutableClients.put(id, Set.copyOf(roles)));
    return new Grants(Set.copyOf(realmRoles), Map.copyOf(immutableClients), Map.copyOf(groupRows), Map.copyOf(paths));
  }

  private static String path(String id, Map<String, Group> groups, Map<String, String> paths, Set<String> visiting) {
    if (paths.containsKey(id)) return paths.get(id);
    if (!visiting.add(id) || visiting.size() > 30 || !groups.containsKey(id)) deny();
    var row = groups.get(id);
    String result = (row.parentId() == null ? "" : path(row.parentId(), groups, paths, visiting)) + "/" + row.name();
    if (result.length() > 512) deny();
    visiting.remove(id);
    paths.put(id, result);
    return result;
  }

  static Set<String> ids(EntityManager em, String sql, String id) {
    var result = new TreeSet<String>();
    for (var value : em.createNativeQuery(sql).setParameter("id", id).getResultList())
      if (value == null || !result.add(text(value))) deny();
    return Set.copyOf(result);
  }

  static Object[] one(EntityManager em, String sql, String id) {
    var rows = em.createNativeQuery(sql).setParameter("id", id).getResultList();
    if (rows.size() != 1) deny();
    return (Object[]) rows.get(0);
  }

  static String text(Object value) {
    return value == null ? null : value.toString();
  }

  static boolean flag(Object value) {
    if (value instanceof Boolean flag) return flag;
    if (value instanceof Number flag) return flag.intValue() != 0;
    deny();
    return false;
  }

  private NativeCurrentGrants() {}
}
