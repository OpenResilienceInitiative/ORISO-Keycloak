#!/bin/bash
# Keycloak Realm Backup Script for ORISO Platform

TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
BACKUP_DIR="/home/caritas/Desktop/online-beratung/caritas-workspace/ORISO-Keycloak/backup"
KEYCLOAK_POD=$(kubectl get pods -n caritas -l app=keycloak -o jsonpath='{.items[0].metadata.name}')
REALM_NAME="online-beratung"

echo "🔐 ORISO Keycloak Realm Backup"
echo "=================================================="
echo "Backup started at: $(date)"
echo "Target pod: $KEYCLOAK_POD"
echo "Realm: $REALM_NAME"
echo "Backup directory: $BACKUP_DIR"
echo "=================================================="

if [ -z "$KEYCLOAK_POD" ]; then
    echo "❌ Error: Keycloak pod not found in 'caritas' namespace."
    exit 1
fi

# Method 1: Export realm using kcadm (preferred)
echo ""
echo "📤 Exporting realm using Keycloak Admin CLI..."

# Configure credentials
kubectl exec -it -n caritas "$KEYCLOAK_POD" -- \
    /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080 \
    --realm master \
    --user admin \
    --password admin 2>/dev/null

if [ $? -ne 0 ]; then
    echo "⚠️  Admin CLI authentication failed. Falling back to manual export."
    echo "📋 Please export realm manually from Admin Console:"
    echo "   1. Login to http://91.99.219.182:8089/auth/admin/"
    echo "   2. Select '$REALM_NAME' realm"
    echo "   3. Click 'Export' in left menu"
    echo "   4. Select export options"
    echo "   5. Download and save to: $BACKUP_DIR/realm-$TIMESTAMP.json"
    exit 1
fi

# Export realm
kubectl exec -it -n caritas "$KEYCLOAK_POD" -- \
    /opt/keycloak/bin/kcadm.sh get realms/$REALM_NAME > "$BACKUP_DIR/realm-$TIMESTAMP.json" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "✅ Realm exported successfully: realm-$TIMESTAMP.json"
    
    # Validate JSON
    if jq empty "$BACKUP_DIR/realm-$TIMESTAMP.json" 2>/dev/null; then
        echo "✅ JSON validation passed"
        
        # Create a copy as latest
        cp "$BACKUP_DIR/realm-$TIMESTAMP.json" "$BACKUP_DIR/realm-latest.json"
        echo "✅ Created latest backup: realm-latest.json"
        
        # Update main realm.json
        cp "$BACKUP_DIR/realm-$TIMESTAMP.json" "/home/caritas/Desktop/online-beratung/caritas-workspace/ORISO-Keycloak/realm.json"
        echo "✅ Updated main realm.json"
    else
        echo "❌ JSON validation failed. Backup may be corrupted."
        exit 1
    fi
else
    echo "❌ Realm export failed."
    exit 1
fi

# Show backup info
BACKUP_SIZE=$(du -h "$BACKUP_DIR/realm-$TIMESTAMP.json" | cut -f1)
echo ""
echo "=================================================="
echo "✅ Backup completed successfully!"
echo "File: realm-$TIMESTAMP.json"
echo "Size: $BACKUP_SIZE"
echo "Location: $BACKUP_DIR"
echo "=================================================="

# Cleanup old backups (keep last 10)
echo ""
echo "🧹 Cleaning up old backups (keeping last 10)..."
cd "$BACKUP_DIR" || exit
ls -t realm-*.json | tail -n +11 | xargs -r rm
echo "✅ Cleanup complete"

# List all backups
echo ""
echo "📁 Available backups:"
ls -lh "$BACKUP_DIR"/realm-*.json | awk '{print $9, $5}'

echo ""
echo "Backup completed at: $(date)"

