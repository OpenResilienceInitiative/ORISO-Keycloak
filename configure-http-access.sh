#!/bin/bash
# Configure Keycloak for HTTP Access (Disable SSL Requirement)
# CRITICAL: This must be run after Keycloak deployment

echo "🔐 Configuring Keycloak for HTTP Access"
echo "=================================================="
echo "This script disables SSL requirement for all realms"
echo "Started at: $(date)"
echo "=================================================="

# Wait for Keycloak to be fully ready
echo ""
echo "⏳ Waiting for Keycloak to be ready (60 seconds)..."
sleep 60

# Get Keycloak pod name
echo ""
echo "🔍 Finding Keycloak pod..."
KEYCLOAK_POD=$(kubectl get pods -n caritas -l app=keycloak -o jsonpath="{.items[0].metadata.name}")

if [ -z "$KEYCLOAK_POD" ]; then
    echo "❌ Error: Keycloak pod not found in 'caritas' namespace."
    exit 1
fi

echo "✅ Found Keycloak pod: $KEYCLOAK_POD"

# Login to kcadm and configure credentials
echo ""
echo "🔑 Configuring kcadm credentials..."
kubectl exec -n caritas $KEYCLOAK_POD -- \
    /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080 \
    --realm master \
    --user admin \
    --password admin

if [ $? -eq 0 ]; then
    echo "✅ kcadm credentials configured successfully"
else
    echo "❌ Failed to configure kcadm credentials"
    exit 1
fi

# Set sslRequired=NONE for master realm
echo ""
echo "🔓 Disabling SSL requirement for master realm..."
kubectl exec -n caritas $KEYCLOAK_POD -- \
    /opt/keycloak/bin/kcadm.sh update realms/master -s sslRequired=NONE

if [ $? -eq 0 ]; then
    echo "✅ SSL requirement disabled for master realm"
else
    echo "❌ Failed to update master realm"
    exit 1
fi

# Apply sslRequired=NONE to all realms
echo ""
echo "🔓 Disabling SSL requirement for all realms..."
kubectl exec -n caritas $KEYCLOAK_POD -- bash -c '
/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin
for r in $(/opt/keycloak/bin/kcadm.sh get realms --fields realm --format csv | tail -n +2); do
  echo "   Processing realm: $r"
  /opt/keycloak/bin/kcadm.sh update realms/"$r" -s sslRequired=NONE
done'

if [ $? -eq 0 ]; then
    echo "✅ SSL requirement disabled for all realms"
else
    echo "⚠️  Some realms may have failed to update"
fi

# Verify configuration
echo ""
echo "🔍 Verifying configuration..."
kubectl exec -n caritas $KEYCLOAK_POD -- \
    /opt/keycloak/bin/kcadm.sh get realms/online-beratung --fields sslRequired

echo ""
echo "=================================================="
echo "✅ Keycloak HTTP Access Configuration Complete!"
echo "=================================================="
echo ""
echo "Keycloak is now configured for HTTP access"
echo "All realms have sslRequired=NONE"
echo ""
echo "You can now access Keycloak via HTTP:"
echo "  - http://91.99.219.182:8089/auth/admin/"
echo "  - http://91.99.219.182:8089/auth/realms/online-beratung"
echo ""
echo "Completed at: $(date)"

