# ORISO Keycloak — vendored OTP plus default-off bounded account and SMTP SPIs.
# Installing providers does not enable Scenario C or grant its routine actors.
#
# The `oriso` email theme carries the otp-email.ftl template the SPI's mail
# sender renders for email-OTP; the realm's emailTheme must be set to `oriso`.

ARG MAVEN_IMAGE=maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320
ARG KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.6.3@sha256:9b0330756022422149aa6502eb2def8cd47c6e1b000c7c65cdb13e7c0133e992

FROM ${MAVEN_IMAGE} AS maven-build
ENV MAVEN_OPTS="-Xmx512m -XX:MaxMetaspaceSize=256m -XX:ActiveProcessorCount=2"
WORKDIR /build

FROM maven-build AS spi-build
COPY otp-config-spi/pom.xml .
COPY otp-config-spi/api ./api
COPY otp-config-spi/src ./src
RUN mvn -q -B package -DskipTests

FROM maven-build AS smtp-build
COPY smtp-control-spi/pom.xml .
COPY smtp-control-spi/src ./src
RUN mvn -q -B package -DskipTests

FROM maven-build AS lifecycle-build
COPY account-lifecycle-spi/pom.xml .
COPY account-lifecycle-spi/src ./src
RUN mvn -q -B package -DskipTests

FROM ${KEYCLOAK_IMAGE} AS builder
COPY --from=spi-build /build/target/keycloak-otp-config-spi-*-keycloak.jar /opt/keycloak/providers/
COPY --from=smtp-build /build/target/smtp-control-spi-1.0-SNAPSHOT.jar /opt/keycloak/providers/
COPY --from=lifecycle-build /build/target/account-lifecycle-spi-1.0-SNAPSHOT.jar /opt/keycloak/providers/
COPY themes/ /opt/keycloak/themes/
RUN /opt/keycloak/bin/kc.sh build

FROM ${KEYCLOAK_IMAGE}
COPY --from=builder /opt/keycloak/ /opt/keycloak/
# The realm contract check travels with the image so the deploy-time job and the
# operator run the same file. A copy in the chart would drift from this one the
# same way a live realm drifts from realm.json.
COPY --chmod=0755 scripts/keycloak-verify-2fa-flow.sh /opt/keycloak/bin/oriso-verify-2fa-flow.sh
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
