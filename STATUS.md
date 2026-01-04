# ORISO-Keycloak Status

## 🟢 Current Status: **RUNNING**

Last Updated: 2025-10-31

## 📊 Deployment Information

### Kubernetes Deployment
- **Namespace**: `caritas`
- **Pod Name**: `keycloak-554947bfb4-9v5fh`
- **Status**: Running (1/1)
- **Uptime**: 17 days
- **Image**: `quay.io/keycloak/keycloak:20.0.5`

### Network Configuration
- **ClusterIP**: `10.43.63.186`
- **HTTP Port**: `8080`
- **HTTPS Port**: `8443`
- **External Access**: Via Nginx proxy at `http://91.99.219.182:8089/auth/`

## 🔑 Access Points

| Endpoint | URL | Access |
|----------|-----|--------|
| Admin Console | `http://91.99.219.182:8089/auth/admin/` | Admin only |
| Realm Endpoint | `http://91.99.219.182:8089/auth/realms/online-beratung` | Public |
| Token Endpoint | `http://91.99.219.182:8089/auth/realms/online-beratung/protocol/openid-connect/token` | Public |
| Internal Service | `http://10.43.63.186:8080` | Cluster only |
| Internal Service | `http://keycloak.caritas.svc.cluster.local:8080` | Cluster DNS |

## ⚙️ Configuration Summary

### Realm: online-beratung
- **Client ID**: `app`
- **Client Type**: Public (SPA)
- **Authentication Flow**: Authorization Code + PKCE
- **Access Token Lifespan**: 18000s (5 hours)
- **SSO Session Timeout**: 1800s (30 minutes)
- **Users**: Active user base
- **Roles**: 7 realm roles configured
- **SSL Required**: NONE (configured for HTTP access)

### HTTP Access Configuration
✅ **SSL Requirement**: Disabled (`sslRequired=NONE`)  
✅ **HTTP Access**: Enabled for all realms  
✅ **Nginx Proxy**: Handles SSL termination externally  
⚠️ **Important**: This configuration must be applied after every fresh Keycloak deployment

### Integration Status
✅ **TenantService** - Integrated  
✅ **UserService** - Integrated  
✅ **AgencyService** - Integrated  
✅ **ConsultingTypeService** - Integrated  
✅ **Frontend** - Integrated  
✅ **Admin** - Integrated

## 📈 Performance Metrics

### Resource Usage
- **CPU**: ~50-100m (low usage)
- **Memory**: ~512Mi-1Gi
- **Replicas**: 1
- **Restart Count**: 0

### Health Status
```bash
# Check health
curl http://10.43.63.186:8080/health
# Expected: {"status":"UP"}
```

## 🔄 Recent Changes

- **2025-10-31**: Exported current configuration to ORISO-Keycloak repository
- **2025-10-14**: Keycloak deployed and running stable for 17 days
- **Last Realm Update**: Included in realm.json

## 🚨 Known Issues

### Active Issues
- ❌ **matrix-keycloak-sync CronJob**: Failing (CrashLoopBackOff)
  - Impact: Low (sync is optional)
  - Solution: Review sync script and fix

### Resolved Issues
- None recent

## 🔐 Security Status

- ✅ Admin credentials: Secured (not in repo)
- ✅ HTTPS: Configured via Nginx proxy
- ⚠️ Direct HTTP: Still enabled (should disable in production)
- ✅ Token validation: Working correctly
- ✅ CORS: Configured properly

## 🛠️ Maintenance Schedule

### Regular Tasks
- **Daily**: Monitor logs for errors
- **Weekly**: Check resource usage
- **Monthly**: Review and backup realm configuration
- **Quarterly**: Review security settings and token lifespans

### Backup Status
- **Last Backup**: Included in this repository
- **Backup Location**: `realm.json`
- **Database Backup**: Managed by Kubernetes (persistent volume)

## 📊 Monitoring

### Logs
```bash
# View current logs
kubectl logs -n caritas deployment/keycloak --tail=100

# Follow logs
kubectl logs -n caritas deployment/keycloak -f

# Check for errors
kubectl logs -n caritas deployment/keycloak | grep -i error
```

### Health Checks
```bash
# Pod status
kubectl get pod -n caritas | grep keycloak

# Service endpoints
kubectl get endpoints -n caritas keycloak

# Deployment status
kubectl get deployment -n caritas keycloak
```

## 🎯 Next Steps

1. ✅ Export and document current configuration
2. ⏳ Fix matrix-keycloak-sync CronJob
3. ⏳ Implement automated realm backups
4. ⏳ Set up monitoring and alerting
5. ⏳ Review and tighten security settings for production

## 📞 Support

For Keycloak-related issues:
1. Check logs: `kubectl logs -n caritas deployment/keycloak`
2. Verify service: `kubectl get svc -n caritas keycloak`
3. Test authentication: Use token endpoint to get access token
4. Review realm configuration: Check Admin Console

---

**Status**: 🟢 Operational  
**Confidence**: High  
**Last Verified**: 2025-10-31

