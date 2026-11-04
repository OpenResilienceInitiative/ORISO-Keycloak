package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;

/** Strict installation-policy parsing shared by the distinct human authority policies. */
final class HumanPolicyJson {
  static Set<String> strings(JsonNode array, int minimum, int maximum, int length) {
    if (array == null || !array.isArray() || array.size() < minimum || array.size() > maximum) bad();
    var values = new LinkedHashSet<String>();
    String previous = null;
    for (var value : array) {
      if (!value.isTextual() || value.asText().isBlank() || value.asText().length() > length
          || value.asText().chars().anyMatch(c -> c < 32 || c == 127)
          || previous != null && previous.compareTo(value.asText()) >= 0) bad();
      previous = value.asText();
      values.add(previous);
    }
    return Set.copyOf(values);
  }

  static Set<Set<String>> audiences(JsonNode value) {
    if (value == null || !value.isArray() || value.isEmpty() || value.size() > 20) bad();
    var result = new HashSet<Set<String>>();
    for (var audience : value) if (!result.add(strings(audience, 1, 30, 255))) bad();
    return Set.copyOf(result);
  }

  static Map<String, Set<String>> clientRoles(JsonNode value) {
    if (value == null || !value.isObject() || value.size() > 30) bad();
    var result = new TreeMap<String, Set<String>>();
    value.fields().forEachRemaining(entry -> {
      String id = entry.getKey();
      if (id.isBlank() || id.length() > 255 || id.chars().anyMatch(c -> c < 32 || c == 127)) bad();
      result.put(id, strings(entry.getValue(), 1, 100, 255));
    });
    return Map.copyOf(result);
  }

  static Set<Long> tenants(JsonNode value) {
    if (value == null || !value.isArray() || value.isEmpty() || value.size() > 100) bad();
    var result = new LinkedHashSet<Long>();
    long previous = -1;
    for (var item : value) {
      if (!item.isIntegralNumber() || !item.canConvertToLong() || item.asLong() <= previous) bad();
      previous = item.asLong();
      result.add(previous);
    }
    return Set.copyOf(result);
  }

  private HumanPolicyJson() {}
}
