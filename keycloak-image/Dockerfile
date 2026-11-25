# ORISO Keycloak — vendored OTP plus default-off bounded account and SMTP SPIs.
# Installing providers does not enable Scenario C or grant its routine actors.
#
# The `oriso` email theme carries the otp-email.ftl template the SPI's mail
# sender renders for email-OTP; the realm's emailTheme must be set to `oriso`.

ARG MAVEN_IMAGE=maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320
ARG KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.8.2-3@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3

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
# Keycloak 26.8.2 still bundles Guava 33.6.0-jre (fixed in 33.7.2-jre; upstream
# keycloak/keycloak#54855). Replace the jar bytes in place, keeping the file name
# that the Quarkus application index refers to, and let `kc.sh build` below
# re-augment against the patched library. Remove this block once the pinned
# upstream image ships Guava >= 33.7.2.
ADD --chmod=0644 --checksum=sha256:b530942257fb935f8b2cfaa5f8eb5bd59c555fd8e8d01b8ce98912e077ea606c \
    https://repo1.maven.org/maven2/com/google/guava/guava/33.7.2-jre/guava-33.7.2-jre.jar \
    /opt/keycloak/lib/lib/main/com.google.guava.guava-33.6.0-jre.jar
COPY --from=spi-build /build/target/keycloak-otp-config-spi-*-keycloak.jar /opt/keycloak/providers/
COPY --from=smtp-build /build/target/smtp-control-spi-1.0-SNAPSHOT.jar /opt/keycloak/providers/
COPY --from=lifecycle-build /build/target/account-lifecycle-spi-1.0-SNAPSHOT.jar /opt/keycloak/providers/
COPY themes/ /opt/keycloak/themes/
RUN /opt/keycloak/bin/kc.sh build

FROM ${KEYCLOAK_IMAGE}
COPY --from=builder /opt/keycloak/ /opt/keycloak/
# Keycloak 26.8.2 (CVE-2026-19688) rejects Admin API tokens from clients without
# the new `kc-admin-api` scope. ORISO services call the Admin API through their
# own clients (backend-admin, backend-technical, task identities), which do not
# have that scope yet. Keep the 26.6.3 behaviour until the realm assigns the
# scope; remove this line in that follow-up, before Staging.
ENV KC_SPI_ADMIN__AUDIENCE_CHECK_ENABLED=false
# The realm contract check travels with the image so the deploy-time job and the
# operator run the same file. A copy in the chart would drift from this one the
# same way a live realm drifts from realm.json.
COPY --chmod=0755 scripts/keycloak-verify-2fa-flow.sh /opt/keycloak/bin/oriso-verify-2fa-flow.sh
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
