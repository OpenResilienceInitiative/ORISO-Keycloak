# ORISO-Keycloak

This repository contains the Keycloak authentication and authorization configuration for the ORISO (Online Beratung) platform.

## 📋 Overview

**Keycloak** is the central identity and access management (IAM) solution for the ORISO platform, providing:
- Single Sign-On (SSO) for all services
- OAuth2/OIDC authentication
- User and role management
- JWT token issuance and validation
- Multi-tenant support

## 🔑 Current Configuration

### Access Information
- **Admin Console**: `http://91.99.219.182:8080/admin/`
- **Realm**: `online-beratung`
- **Internal Service**: `http://10.43.63.186:8080`
- **Ports**:
  - `8080` - HTTP
  - `8443` - HTTPS
- **Namespace**: `caritas` (Kubernetes)

### Realm Configuration
The `realm.json` file contains the complete realm configuration including:
- **Client**: `app` (main frontend application)
- **Roles**:
  - `consultant` - Consultant role
  - `user` - Regular user role
  - `user-admin` - User administration role
  - `agency-admin` - Agency administration role
  - `tenant-admin` - Tenant administration role
  - `technical` - Technical role for service accounts
- **Custom Scopes**: `app-custom` (includes username, tenantId, userId claims)
- **Token Lifespans**:
  - Access Token: 18000s (5 hours)
  - SSO Session Idle Timeout: 1800s (30 minutes)
  - SSO Session Max Lifespan: 36000s (10 hours)

## 📁 Repository Contents

```
ORISO-Keycloak/
├── README.md                      # This file
├── DEPLOYMENT.md                  # Deployment guide
├── STATUS.md                      # Current status
├── realm.json                     # Keycloak realm configuration
├── keycloak-deployment.yaml       # Kubernetes deployment
├── keycloak-service.yaml          # Kubernetes service
├── configure-http-access.sh       # HTTP access configuration (CRITICAL)
└── backup/
    └── realm-backup.sh            # Backup script
```

## 🚀 Quick Start

### Configure HTTP Access (CRITICAL FIRST STEP)

**IMPORTANT**: After deploying Keycloak, you must disable SSL requirement for HTTP access.

```bash
# Run the automated configuration script
cd /home/caritas/Desktop/online-beratung/caritas-workspace/ORISO-Keycloak
./configure-http-access.sh
```

This script:
- Configures kcadm credentials
- Sets `sslRequired=NONE` for master realm
- Applies `sslRequired=NONE` to all realms (including online-beratung)

**Why this is needed**: Keycloak requires HTTPS by default for external requests. Since ORISO uses HTTP internally (with Nginx handling SSL termination), this configuration is essential.

### Import Realm Configuration

```bash
# Method 1: Via Keycloak Admin Console
# 1. Login to Keycloak Admin Console
# 2. Select "Master" realm dropdown -> "Add realm"
# 3. Click "Select file" and upload realm.json
# 4. Click "Create"

# Method 2: Via CLI (when starting Keycloak)
docker run -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -v $(pwd)/realm.json:/opt/keycloak/data/import/realm.json \
  -p 8080:8080 \
  quay.io/keycloak/keycloak:20.0.5 start-dev \
  --import-realm
```

### Export Realm Configuration

```bash
# Using Keycloak Admin Console
# 1. Login to Keycloak Admin Console
# 2. Select "online-beratung" realm
# 3. Click "Export" in the left menu
# 4. Select export options and download

# Or use the backup script
./backup/realm-backup.sh
```

## 🔧 Integration with ORISO Services

### Service Configuration
All ORISO backend services use Keycloak for authentication. Example Spring Boot configuration:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://keycloak.caritas.svc.cluster.local:8080/realms/online-beratung
          jwk-set-uri: http://keycloak.caritas.svc.cluster.local:8080/realms/online-beratung/protocol/openid-connect/certs
```

### Frontend Configuration
The frontend uses Keycloak's JavaScript adapter:

```javascript
const keycloak = new Keycloak({
  url: 'http://91.99.219.182:8080',
  realm: 'online-beratung',
  clientId: 'app'
});
```

## 🔐 Security Considerations

1. **Admin Credentials**: Store securely, never commit to git
2. **Client Secrets**: Use environment variables for client secrets
3. **HTTPS**: Enable HTTPS in production with valid SSL certificates
4. **Token Lifespans**: Review and adjust based on security requirements
5. **Password Policies**: Configure strong password policies in realm settings

## 🛠️ Maintenance

### Update Realm Configuration
```bash
# 1. Export current realm configuration from Admin Console
# 2. Save as realm.json in this repository
# 3. Review changes
git diff realm.json
# 4. Commit and push
git add realm.json
git commit -m "Update realm configuration"
git push
```

### Backup Strategy
- **Automated**: Use the backup script in `backup/realm-backup.sh`
- **Manual**: Export realm regularly via Admin Console
- **Database**: Backup Keycloak's PostgreSQL/MariaDB database

## 📊 Monitoring

### Health Check
```bash
curl http://10.43.63.186:8080/health
```

### Metrics
Keycloak exposes metrics at:
```
http://10.43.63.186:8080/metrics
```

## 🐛 Troubleshooting

### Issue: "HTTPS required" or SSL errors
**Solution**: Run the HTTP access configuration script
```bash
cd /home/caritas/Desktop/online-beratung/caritas-workspace/ORISO-Keycloak
./configure-http-access.sh
```
This disables SSL requirement for all realms.

### Issue: Token Validation Fails
**Solution**: Check that service's `issuer-uri` matches Keycloak realm URL

### Issue: Admin Console Not Accessible
**Solution**:
```bash
kubectl port-forward -n caritas svc/keycloak 8080:8080
```

### Issue: Users Can't Login
**Solution**: Check Keycloak logs
```bash
kubectl logs -n caritas deployment/keycloak
```

### Issue: "Redirect URI mismatch" errors
**Solution**: Verify that the client's redirect URIs include your application URL in Keycloak Admin Console

## 📚 Resources

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)
- [Keycloak Securing Apps Guide](https://www.keycloak.org/docs/latest/securing_apps/)

## 🔄 Version Information

- **Keycloak Version**: 20.0.5
- **Realm**: online-beratung
- **Last Updated**: 2025-10-31

---

**Part of the ORISO Platform**  
For more information, see the main ORISO-OVERVIEW.md

