package org.oriso.keycloak.lifecycle;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;

final class LifecycleJson {
  static final ObjectMapper JSON =
      new ObjectMapper()
          .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
          .enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

  static JsonNode parse(byte[] raw) {
    if (raw == null || raw.length > 65536) bad();
    try {
      String decoded =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
              .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
              .decode(java.nio.ByteBuffer.wrap(raw))
              .toString();
      return parse(decoded);
    } catch (java.nio.charset.CharacterCodingException failure) {
      throw new BadRequestException("Invalid lifecycle UTF8");
    }
  }

  static JsonNode parse(String raw) {
    try {
      if (raw == null || raw.getBytes(StandardCharsets.UTF_8).length > 65536) bad();
      JsonNode value = JSON.readTree(raw);
      if (value == null || !value.isObject()) bad();
      canonical(value);
      return value;
    } catch (BadRequestException failure) {
      throw failure;
    } catch (Exception failure) {
      throw new BadRequestException("Invalid lifecycle request");
    }
  }

  static void fields(JsonNode value, String... expected) {
    if (value == null || !value.isObject()) bad();
    Set<String> actual = new HashSet<>();
    value.fieldNames().forEachRemaining(actual::add);
    if (!actual.equals(Set.of(expected))) bad();
  }

  static String text(JsonNode value, String field, int limit, boolean nullable) {
    JsonNode node = value.get(field);
    if (nullable && node != null && node.isNull()) return null;
    if (node == null
        || !node.isTextual()
        || !nullable && node.asText().isBlank()
        || node.asText().length() > limit
        || node.asText().chars().anyMatch(c -> c < 32 || c == 127)) bad();
    return node.asText();
  }

  static String uuid(String value) {
    try {
      if (value == null || !UUID.fromString(value).toString().equals(value)) bad();
    } catch (IllegalArgumentException failure) {
      bad();
    }
    return value;
  }

  static long number(JsonNode value, String field, boolean positive) {
    JsonNode node = value.get(field);
    if (node == null
        || !node.isIntegralNumber()
        || !node.canConvertToLong()
        || node.asLong() < (positive ? 1 : 0)) bad();
    return node.asLong();
  }

  static void hex(String value) {
    if (value == null || !value.matches("[a-f0-9]{64}")) bad();
  }

  static JsonNode sorted(JsonNode value) {
    if (value.isObject()) {
      ObjectNode result = JSON.createObjectNode();
      TreeMap<String, JsonNode> entries = new TreeMap<>();
      value.fields().forEachRemaining(e -> entries.put(e.getKey(), e.getValue()));
      entries.forEach((k, v) -> result.set(k, sorted(v)));
      return result;
    }
    if (value.isArray()) {
      var result = JSON.createArrayNode();
      value.forEach(v -> result.add(sorted(v)));
      return result;
    }
    if (!value.isNull() && !value.isBoolean() && !value.isTextual() && !value.isIntegralNumber())
      bad();
    return value;
  }

  static String canonical(JsonNode value) {
    try {
      return JSON.writeValueAsString(sorted(value));
    } catch (Exception failure) {
      throw new BadRequestException("Invalid lifecycle request");
    }
  }

  static void execution(JsonNode value) {
    fields(value, "executionId", "generation");
    uuid(text(value, "executionId", 36, false));
    number(value, "generation", false);
  }

  static void outcome(JsonNode value) {
    fields(value, "journalVersion", "outboxId", "effectsDigest");
    number(value, "journalVersion", true);
    uuid(text(value, "outboxId", 36, false));
    hex(text(value, "effectsDigest", 64, false));
  }

  static void bad() {
    throw new BadRequestException("Invalid lifecycle request");
  }

  static void deny() {
    throw new ForbiddenException("Lifecycle command is not authorized");
  }

  private LifecycleJson() {}
}
