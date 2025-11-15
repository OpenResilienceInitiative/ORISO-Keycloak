# ORISO-Keycloak Deployment Guide

This guide provides detailed instructions for deploying Keycloak for the ORISO platform.

## 📋 Prerequisites

- Kubernetes cluster (k3s)
- kubectl configured
- Database (PostgreSQL or MariaDB) for production
- SSL certificates for HTTPS (production)

## ⚠️ Important Note: HTTP Access Configuration

**CRITICAL**: Keycloak requires HTTPS by default. After deployment, you **must** run the HTTP access configuration script to disable SSL requirement. Without this, authentication will fail with "HTTPS required" errors.

```bash
./configure-http-access.sh
```

This is especially important for the ORISO setup where:
- Nginx handles SSL termination
- Internal services communicate via HTTP
- Keycloak needs to accept HTTP requests from internal services

## 🚀 Deployment Options

### Option 1: Deploy to Kubernetes (Recommended)

#### Step 1: Apply Kubernetes Configurations

```bash
# Apply service first
kubectl apply -f keycloak-service.yaml

# Apply deployment
kubectl apply -f keycloak-deployment.yaml
```

#### Step 2: Verify Deployment

```bash
# Check pod status
kubectl get pods -n caritas | grep keycloak

# Check service
kubectl get svc -n caritas | grep keycloak

# View logs
kubectl logs -n caritas deployment/keycloak
```

#### Step 3: Configure HTTP Access (CRITICAL)

**IMPORTANT**: Keycloak requires SSL by default. You must disable this for HTTP access.

```bash
# Run the HTTP access configuration script
cd /home/caritas/Desktop/online-beratung/caritas-workspace/ORISO-Keycloak
./configure-http-access.sh

# Or manually configure:
KEYCLOAK_POD=$(kubectl get pods -n caritas -l app=keycloak -o jsonpath="{.items[0].metadata.name}")

# Configure kcadm credentials
kubectl exec -n caritas $KEYCLOAK_POD -- \
  /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 --realm master \
  --user admin --password admin

# Disable SSL for master realm
kubectl exec -n caritas $KEYCLOAK_POD -- \
  /opt/keycloak/bin/kcadm.sh update realms/master -s sslRequired=NONE

# Disable SSL for all realms
kubectl exec -n caritas $KEYCLOAK_POD -- bash -c '
/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --realm master --user admin --password admin
for r in $(/opt/keycloak/bin/kcadm.sh get realms --fields realm --format csv | tail -n +2); do
  /opt/keycloak/bin/kcadm.sh update realms/"$r" -s sslRequired=NONE
done'
```

#### Step 4: Import Realm

```bash
# Port-forward to access Keycloak
kubectl port-forward -n caritas svc/keycloak 8080:8080

# Access Admin Console at http://localhost:8080/admin
# Login with admin credentials
# Import realm.json via Admin Console
```

### Option 2: Deploy with Docker

```bash
# Development mode
docker run -d \
  --name keycloak \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=yourpassword \
  -v $(pwd)/realm.json:/opt/keycloak/data/import/realm.json \
  -p 8080:8080 \
  quay.io/keycloak/keycloak:20.0.5 start-dev --import-realm

# Production mode with external database
docker run -d \
  --name keycloak \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=yourpassword \
  -e KC_DB=postgres \
  -e KC_DB_URL=jdbc:postgresql://db-host:5432/keycloak \
  -e KC_DB_USERNAME=keycloak \
  -e KC_DB_PASSWORD=dbpassword \
  -e KC_HOSTNAME=yourdomain.com \
  -v $(pwd)/realm.json:/opt/keycloak/data/import/realm.json \
  -p 8080:8080 \
  -p 8443:8443 \
  quay.io/keycloak/keycloak:20.0.5 start --import-realm
```

### Option 3: Deploy with Helm

```bash
# Add Bitnami Helm repository
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Create values file
cat > keycloak-values.yaml <<EOF
auth:
  adminUser: admin
  adminPassword: yourpassword

postgresql:
  enabled: true
  auth:
    username: keycloak
    password: dbpassword
    database: keycloak

service:
  type: ClusterIP
  port: 8080

ingress:
  enabled: false

replicaCount: 1
EOF

# Install Keycloak
helm install keycloak bitnami/keycloak \
  -n caritas \
  -f keycloak-values.yaml

# Import realm after deployment
kubectl port-forward -n caritas svc/keycloak 8080:8080
# Then import realm.json via Admin Console
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `KEYCLOAK_ADMIN` | Admin username | admin | Yes |
| `KEYCLOAK_ADMIN_PASSWORD` | Admin password | - | Yes |
| `KC_DB` | Database type (postgres, mysql, mariadb) | h2 (dev) | Production |
| `KC_DB_URL` | Database JDBC URL | - | Production |
| `KC_DB_USERNAME` | Database username | - | Production |
| `KC_DB_PASSWORD` | Database password | - | Production |
| `KC_HOSTNAME` | Public hostname | localhost | Production |
| `KC_HTTP_ENABLED` | Enable HTTP | true | - |
| `KC_HTTPS_ENABLED` | Enable HTTPS | false | Production |

### Database Configuration

#### PostgreSQL (Recommended)
```bash
# Create database
psql -U postgres -c "CREATE DATABASE keycloak;"
psql -U postgres -c "CREATE USER keycloak WITH PASSWORD 'password';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;"

# Configure Keycloak
KC_DB=postgres
KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak
KC_DB_USERNAME=keycloak
KC_DB_PASSWORD=password
```

#### MariaDB
```bash
# Create database
mysql -u root -p -e "CREATE DATABASE keycloak CHARACTER SET utf8 COLLATE utf8_unicode_ci;"
mysql -u root -p -e "CREATE USER 'keycloak'@'%' IDENTIFIED BY 'password';"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON keycloak.* TO 'keycloak'@'%';"
mysql -u root -p -e "FLUSH PRIVILEGES;"

# Configure Keycloak
KC_DB=mariadb
KC_DB_URL=jdbc:mariadb://mariadb:3306/keycloak
KC_DB_USERNAME=keycloak
KC_DB_PASSWORD=password
```

## 🔐 SSL/TLS Configuration

### Using Let's Encrypt

```bash
# Generate certificates with certbot
certbot certonly --standalone -d yourdomain.com

# Mount certificates in Keycloak
-v /etc/letsencrypt/live/yourdomain.com/fullchain.pem:/opt/keycloak/conf/server.crt.pem
-v /etc/letsencrypt/live/yourdomain.com/privkey.pem:/opt/keycloak/conf/server.key.pem

# Enable HTTPS
KC_HTTPS_ENABLED=true
KC_HTTPS_CERTIFICATE_FILE=/opt/keycloak/conf/server.crt.pem
KC_HTTPS_CERTIFICATE_KEY_FILE=/opt/keycloak/conf/server.key.pem
```

### Using Nginx Reverse Proxy (Current Setup)

The ORISO platform uses Nginx as a reverse proxy for Keycloak:

```nginx
# Nginx configuration (already in ORISO-Nginx)
location /auth/ {
    proxy_pass http://10.43.63.186:8080/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

## 📊 Post-Deployment Verification

### 1. Health Check
```bash
curl http://keycloak:8080/health
```

### 2. Verify Realm Import
```bash
# Login to Admin Console
# Navigate to Realms dropdown
# Verify "online-beratung" realm exists
```

### 3. Test Authentication
```bash
# Get access token
curl -X POST "http://keycloak:8080/realms/online-beratung/protocol/openid-connect/token" \
  -d "client_id=app" \
  -d "username=testuser" \
  -d "password=testpass" \
  -d "grant_type=password"
```

### 4. Verify Service Integration
```bash
# Test backend service authentication
curl -H "Authorization: Bearer <token>" \
  http://tenantservice:8081/tenants
```

## 🔄 Updates and Maintenance

### Update Realm Configuration
```bash
# Export current realm
kubectl port-forward -n caritas svc/keycloak 8080:8080
# Access Admin Console -> Export realm

# Or use Keycloak Admin CLI
kubectl exec -it -n caritas deployment/keycloak -- \
  /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user admin

kubectl exec -it -n caritas deployment/keycloak -- \
  /opt/keycloak/bin/kcadm.sh get realms/online-beratung > realm-export.json
```

### Upgrade Keycloak Version
```bash
# 1. Backup current realm and database
./backup/realm-backup.sh

# 2. Update image version in keycloak-deployment.yaml
image: quay.io/keycloak/keycloak:21.0.0  # New version

# 3. Apply update
kubectl apply -f keycloak-deployment.yaml

# 4. Monitor rollout
kubectl rollout status deployment/keycloak -n caritas

# 5. Verify
kubectl logs -n caritas deployment/keycloak
```

## 🐛 Troubleshooting

### Issue: Pods Not Starting
```bash
# Check pod events
kubectl describe pod -n caritas <keycloak-pod-name>

# Check logs
kubectl logs -n caritas <keycloak-pod-name>

# Common causes:
# - Database connection issues
# - Invalid admin credentials
# - Insufficient resources
```

### Issue: Cannot Access Admin Console
```bash
# Port-forward to pod
kubectl port-forward -n caritas pod/<keycloak-pod-name> 8080:8080

# Check service
kubectl get svc -n caritas keycloak

# Check firewall rules
sudo ufw status
```

### Issue: Realm Import Fails
```bash
# Check realm.json syntax
jq . realm.json

# Import via CLI instead
kubectl cp realm.json <keycloak-pod-name>:/tmp/realm.json
kubectl exec -it <keycloak-pod-name> -- \
  /opt/keycloak/bin/kcadm.sh create partialImport \
  -r online-beratung -f /tmp/realm.json
```

## 📈 Scaling

### Horizontal Scaling
```bash
# Scale Keycloak deployment
kubectl scale deployment keycloak --replicas=3 -n caritas

# Note: Requires external database (not H2)
# Note: Session replication should be configured
```

### Performance Tuning
```yaml
# In keycloak-deployment.yaml
resources:
  requests:
    memory: "1Gi"
    cpu: "500m"
  limits:
    memory: "2Gi"
    cpu: "1000m"

# Java options
env:
- name: JAVA_OPTS
  value: "-Xms1024m -Xmx2048m -XX:MetaspaceSize=256m"
```

## 🔒 Security Checklist

- [ ] Change default admin password
- [ ] Enable HTTPS in production
- [ ] Configure firewall rules
- [ ] Set up database backups
- [ ] Enable audit logging
- [ ] Review and set token lifespans
- [ ] Configure password policies
- [ ] Enable brute force protection
- [ ] Set up monitoring and alerting
- [ ] Review and restrict admin access

---

**Last Updated**: 2025-10-31  
**Part of the ORISO Platform**

