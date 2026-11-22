# Isolated OTP accounting regression probe

The probe starts and removes its own Docker container and loopback SMTP sink. Every identity, password, OTP and realm is synthetic. It never connects to a shared realm. It submits the real OIDC browser form protocol over HTTP; that is separate from interactive browser acceptance.

For developers — reproduce the baseline failure and candidate success:

```sh
python3 scripts/test-otp-brute-force.py --image <exact-baseline-image-digest>
JAVA_HOME=$(/usr/libexec/java_home -v21) mvn -q -f keycloak-image/otp-config-spi/pom.xml package
python3 scripts/test-otp-brute-force.py --image <same-exact-baseline-image-digest> \
  --provider-jar keycloak-image/otp-config-spi/target/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar
```

Baseline RED is the first correct-password email challenge incrementing the account failure count. Candidate assertions cover email cooldown/abandonment, mail cap, wrong-code counting, success/reset, replay, concurrent code use, missing app OTP, real browser wrong/expired codes and replacement, SMTP failure, actual wrong-password lockout and master recovery. The OTP-expiry fixture and mail cooldown are accelerated only inside the synthetic realm. Production account protection fields retain their actual values.

Use an immutable matching image digest. The provider overlay performs a genuine Quarkus rebuild; the probe does not disguise provider timestamps or skip augmentation. AMD64 emulation can take several minutes; startup timeout is an infrastructure failure, not a behavioral verdict. Tokens and passwords never appear in output. The final sanitized assertions say whether the entire run passed.
