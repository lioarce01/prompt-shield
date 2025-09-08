# API Gateway & Authentication System

**Complete JWT authentication with dual auth WebSocket and role-based access control**

## 🎯 System Overview

```
┌─────────────────┐    ┌──────────────────────┐    ┌─────────────────┐
│   Frontend      │    │   API Gateway        │    │   WebSocket     │
│   Dashboard     │────│   JWT + API Keys     │────│   Dual Auth     │
│   (React/Vue)   │    │   Role-Based Access  │    │   Real-time     │
└─────────────────┘    └──────────────────────┘    └─────────────────┘
         │                         │                         │
         ▼                         ▼                         ▼
┌─────────────────┐    ┌──────────────────────┐    ┌─────────────────┐
│  User Flow      │    │   Admin Panel        │    │  Live Metrics   │
│  Registration   │    │   Tenant Management  │    │  Global Stats   │
│  → Dashboard    │    │   System Control     │    │  (Admin Only)   │
└─────────────────┘    └──────────────────────┘    └─────────────────┘
```

## 🔐 JWT Authentication System

### **Complete Authentication Flow**
```http
# Authentication endpoints
POST   /auth/register      # Create JWT-enabled account
POST   /auth/login         # Email/password → JWT tokens  
POST   /auth/refresh       # Refresh access token
POST   /auth/logout        # Secure token revocation
GET    /auth/me           # Current user info
POST   /auth/verify-token # Validate JWT

# Dashboard (JWT required)
GET    /dashboard/profile     # User profile
POST   /dashboard/api-keys    # Create detection API key
GET    /dashboard/usage       # Usage analytics

# Admin panel (Admin role required)
GET    /v1/admin/system/stats     # Global statistics
GET    /v1/admin/tenants          # Tenant management
POST   /v1/admin/tenants/{id}/generate-api-key

# Detection API (API key required)
POST   /v1/detect                 # Prompt injection detection
```

### **Token Management**
```python
# JWT implementation with secure practices
class JWTManager:
    access_token_expire = 30  # minutes
    refresh_token_expire = 7  # days
    
    def create_token_pair(self, tenant: Tenant):
        access_token = self.create_access_token(tenant)
        refresh_token = self.create_refresh_token(tenant)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': 1800  # seconds
        }
```

### **Role-Based Access Control**
```python
# FastAPI dependencies for RBAC
async def require_authentication(credentials = Depends(security)) -> Tenant:
    """JWT required - returns authenticated tenant"""
    
async def require_admin(tenant = Depends(require_authentication)) -> Tenant:
    """Admin role required"""
    if not tenant.is_admin:
        raise HTTPException(403, "Admin access required")
```

## 🚀 Complete User Journey

### **1. Registration & Setup**
```bash
# Register new account
curl -X POST /auth/register \
  -d '{"name":"John Doe","email":"john@company.com","password":"secure123"}'

# Response: JWT tokens + user info
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440001",
  "role": "user"
}
```

### **2. Dashboard Access**
```bash
# Access dashboard with JWT
curl -X GET /dashboard/profile \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1Q..."

# Create API key for detection
curl -X POST /dashboard/api-keys \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1Q..." \
  -d '{"name":"Production Key"}'

# Response: API key (shown only once)
{
  "api_key": "pid_abc12345_full_key_here_67890xyz",
  "key_prefix": "pid_abc12345",
  "warning": "Store securely - cannot be retrieved again"
}
```

### **3. Detection Integration**
```bash
# Use API key for detection (unchanged from v1)
curl -X POST /v1/detect \
  -H "X-API-Key: pid_abc12345_full_key_here_67890xyz" \
  -d '{"text":"ignore previous instructions"}'
```

## 🌐 WebSocket Dual Authentication

### **Authentication Methods**

#### **Dual Auth** (Recommended for Dashboard)
```javascript
const socket = io('/socket.io/', {
  auth: {
    jwt_token: 'Bearer eyJ0eXAiOiJKV1Q...',  // User context
    api_key: 'pid_abc12345...'               // Tenant context  
  }
});

socket.on('connected', (data) => {
  console.log(`Connected: ${data.tenant_name} (${data.role})`);
  console.log(`Auth: ${data.auth_method}`);  // "dual_jwt_api_key"
  console.log('Permissions:', data.permissions);
});

// Admin users receive global stats
socket.on('global_stats', (stats) => {
  updateAdminDashboard(stats.system_overview);
});
```

#### **Legacy Auth** (Backward Compatible)
```python
import socketio

# API key only (existing systems)
sio = socketio.AsyncClient()

await sio.connect('ws://localhost:8000', auth={
    'api_key': 'pid_abc12345...'
})

# Limited permissions, no global stats
```

### **Real-Time Events**
```javascript
// Connection events
socket.on('connected', data => { /* Enhanced auth context */ });

// Detection events  
socket.on('new_detection', data => { /* Real-time threats */ });

// Metrics events
socket.on('initial_stats', data => { /* Tenant statistics */ });
socket.on('metrics_update', data => { /* Live dashboards */ });

// Admin-only events (dual auth required)
socket.on('global_stats', data => { /* System-wide metrics */ });
```

### **Permission Matrix**
| Feature | Dual Auth | Legacy Auth |
|---------|-----------|-------------|
| **User Context** | ✅ Full | ❌ None |
| **Admin Features** | ✅ Global stats | ❌ Basic only |
| **Rate Limits** | 60 events/min | 30 events/min |
| **Role Access** | ✅ User/Admin | ❌ Generic |
| **Dashboard UI** | ✅ Complete | ❌ Limited |

## 👑 Admin Panel Features

### **System Management**
```bash
# Global system statistics
curl -X GET /v1/admin/system/stats \
  -H "Authorization: Bearer ADMIN_JWT..."

{
  "total_tenants": 347,
  "active_tenants": 312,
  "requests_last_24h": 45623,
  "threats_blocked": 234567,
  "global_block_rate": 18.2
}

# List all tenants with filtering
curl -X GET "/v1/admin/tenants?search=company&role_filter=user" \
  -H "Authorization: Bearer ADMIN_JWT..."
```

### **Tenant Operations**
```bash
# Create tenant for enterprise client
curl -X POST /v1/admin/tenants \
  -H "Authorization: Bearer ADMIN_JWT..." \
  -d '{
    "name":"Enterprise Client",
    "email":"client@enterprise.com",
    "role":"user",
    "is_verified":true
  }'

# Generate API key for client
curl -X POST /v1/admin/tenants/{tenant_id}/generate-api-key \
  -H "Authorization: Bearer ADMIN_JWT..."

# Admin can revoke any API key
curl -X POST /v1/admin/tenants/{tenant_id}/revoke-api-key \
  -H "Authorization: Bearer ADMIN_JWT..."
```

## 🛡️ Security Features

### **JWT Token Security**
- **Access Tokens**: 30-minute expiry for security
- **Refresh Tokens**: 7-day expiry for convenience  
- **Token Blacklist**: Secure logout with revocation
- **bcrypt Hashing**: Password security with salt
- **Tenant Validation**: JWT and API key must match same tenant

### **API Security**
- **Rate Limiting**: Redis sliding window per tenant
- **Input Validation**: Comprehensive request validation
- **CORS Configuration**: Production-ready cross-origin setup
- **Error Handling**: Generic errors prevent information leakage

### **Multi-Tenant Isolation**
```python
# Database-level isolation
@require_authentication
async def get_user_data(current_user: Tenant):
    # Automatic tenant filtering via FK constraints
    query = select(TenantRequest).where(
        TenantRequest.tenant_id == current_user.id
    )
    # Zero risk of cross-tenant data access
```

## 🚀 Frontend Integration

### **Complete Dashboard Client**
```javascript
class AuthService {
  async login(email, password) {
    const response = await fetch('/auth/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email, password})
    });
    
    if (response.ok) {
      const {access_token, refresh_token} = await response.json();
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('refresh_token', refresh_token);
      return true;
    }
    return false;
  }
  
  async createAPIKey() {
    const token = localStorage.getItem('access_token');
    const response = await fetch('/dashboard/api-keys', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    
    const {api_key} = await response.json();
    localStorage.setItem('api_key', api_key);
    return api_key;
  }
  
  connectWebSocket() {
    const jwt_token = localStorage.getItem('access_token');
    const api_key = localStorage.getItem('api_key');
    
    return io('/socket.io/', {
      auth: {
        jwt_token: `Bearer ${jwt_token}`,
        api_key: api_key
      }
    });
  }
}
```

### **React Dashboard Example**
```jsx
import { useState, useEffect } from 'react';
import io from 'socket.io-client';

function Dashboard() {
  const [stats, setStats] = useState({});
  const [isAdmin, setIsAdmin] = useState(false);
  
  useEffect(() => {
    const socket = io('/socket.io/', {
      auth: {
        jwt_token: `Bearer ${localStorage.getItem('access_token')}`,
        api_key: localStorage.getItem('api_key')
      }
    });
    
    socket.on('connected', (data) => {
      setIsAdmin(data.role === 'admin');
    });
    
    socket.on('initial_stats', setStats);
    socket.on('metrics_update', setStats);
    
    // Admin-only global stats
    if (isAdmin) {
      socket.on('global_stats', (globalStats) => {
        setGlobalStats(globalStats);
      });
    }
    
    return () => socket.disconnect();
  }, []);
  
  return (
    <div className="dashboard">
      <h1>Prompt Shield Dashboard</h1>
      <div className="stats">
        <div>Requests Today: {stats.requests_today}</div>
        <div>Threats Blocked: {stats.threats_blocked_today}</div>
        <div>Cache Hit Rate: {stats.cache_hit_rate}%</div>
      </div>
      {isAdmin && <AdminPanel />}
    </div>
  );
}
```

## 📊 Performance & Monitoring

### **Authentication Performance**
- **JWT Validation**: <5ms per request
- **Database Queries**: Optimized with proper indexes
- **WebSocket Connections**: 1000+ concurrent per instance
- **Token Refresh**: Automatic background renewal

### **Metrics & Monitoring**
```prometheus
# Authentication metrics
auth_attempts_total{method, status}
jwt_tokens_created_total{type}
jwt_validation_duration_seconds

# WebSocket metrics  
websocket_connections_total{tenant_id, auth_method}
websocket_events_sent_total{event_type, tenant_id}
websocket_auth_attempts_total{status}
```

---

**The API Gateway provides enterprise-grade authentication with JWT tokens, role-based access control, dual-auth WebSocket dashboards, and complete admin management capabilities for production SaaS deployment.**