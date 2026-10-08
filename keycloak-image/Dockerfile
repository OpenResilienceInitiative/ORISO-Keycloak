# ORISO Keycloak — stock Keycloak plus the vendored onlineBeratung otp-config SPI.
# The SPI provides the /realms/<realm>/otp-config REST endpoints the UserService
# calls for 2FA setup, plus the direct-grant authenticators (app + email OTP).
#
# The `oriso` email theme carries the otp-email.ftl template the SPI's mail
# sender renders for email-OTP; the realm's emailTheme must be set to `oriso`.

FROM maven:3.9-eclipse-temurin-21 AS spi-build
WORKDIR /build
COPY pom.xml .
COPY task-auth/ ./task-auth/
COPY task-command-spi/ ./task-command-spi/
COPY otp-config-spi/ ./otp-config-spi/
RUN --mount=type=cache,target=/root/.m2 mvn -q -B package -DskipTests

FROM quay.io/keycloak/keycloak:26.6.3 AS builder
COPY --from=spi-build /build/otp-config-spi/target/keycloak-otp-config-spi-*-keycloak.jar /opt/keycloak/providers/
COPY --from=spi-build /build/task-auth/target/task-auth-*.jar /opt/keycloak/providers/
COPY --from=spi-build /build/task-command-spi/target/task-command-spi-*.jar /opt/keycloak/providers/
COPY themes/ /opt/keycloak/themes/
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.6.3
COPY --from=builder /opt/keycloak/ /opt/keycloak/
# The realm contract check travels with the image so the deploy-time job and the
# operator run the same file. A copy in the chart would drift from this one the
# same way a live realm drifts from realm.json.
COPY --chmod=0755 scripts/keycloak-verify-2fa-flow.sh /opt/keycloak/bin/oriso-verify-2fa-flow.sh
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
