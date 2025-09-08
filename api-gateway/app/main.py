"""
FastAPI Gateway for Prompt Shield Platform - Multi-Tenant Version
Clean implementation with tenant isolation
"""

import logging
import time
from contextlib import asynccontextmanager
from typing import Dict, Any

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# Import tenant-aware routers
from app.api.v1.auth import router as auth_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.detection import router as detection_router
from app.api.v1.tenant_management import router as tenant_management_router
from app.api.v1.websocket_admin import router as websocket_admin_router
from app.api.v1.admin import router as admin_router
from app.api.v1.webhooks import router as webhooks_router
from app.core.config import get_settings
from app.core.database import init_db
from app.services.detection_service import DetectionService

# Import models so SQLAlchemy can create tables
from app.models import tenant as tenant_models

# Import WebSocket functionality
from app.websocket.socketio_server import get_socketio_server, create_socketio_app
from app.websocket.auth import setup_socketio_handlers
from app.websocket.metrics_broadcaster import start_metrics_broadcaster, stop_metrics_broadcaster

# Prometheus metrics
REQUEST_COUNT = Counter('api_requests_total', 'Total API requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('api_request_duration_seconds', 'Request duration', ['method', 'endpoint'])

# Configure structured logging first (before settings)
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown"""
    # Initialize settings safely
    try:
        settings = get_settings()
        app.state.settings = settings
        logger.info("Settings loaded successfully", version=settings.VERSION)
    except Exception as e:
        logger.error("Failed to load settings", error=str(e))
        raise
    
    # Startup
    logger.info("Starting Multi-Tenant API Gateway", version="2.0.0")
    
    # Initialize database with tenant tables
    await init_db()
    logger.info("Database initialized with tenant schema")
    
    # Initialize detection service
    detection_service = DetectionService()
    app.state.detection_service = detection_service
    
    # Test connection to Go detection engine
    try:
        health = await detection_service.health_check()
        logger.info("Detection engine connected", status=health.get("status"))
    except Exception as e:
        logger.warning("Detection engine connection failed, fallback mode will be used", error=str(e))
    
    # Initialize WebSocket server
    try:
        sio = await get_socketio_server()
        await setup_socketio_handlers()
        app.state.socketio_server = sio
        
        # Mount Socket.IO app
        import socketio
        socket_app = socketio.ASGIApp(sio, socketio_path='/socket.io')
        app.mount("/socket.io", socket_app)
        
        # Start metrics broadcaster
        await start_metrics_broadcaster()
        
        logger.info("WebSocket server initialized and mounted at /socket.io with metrics broadcasting")
    except Exception as e:
        logger.error("Failed to initialize WebSocket server", error=str(e))
        # Continue without WebSocket if it fails
    
    yield
    
    # Shutdown
    logger.info("Shutting down Multi-Tenant API Gateway")
    
    # Stop metrics broadcaster
    try:
        await stop_metrics_broadcaster()
        logger.info("Metrics broadcaster stopped")
    except Exception as e:
        logger.warning("Error stopping metrics broadcaster", error=str(e))
    
    if hasattr(app.state, 'detection_service'):
        await app.state.detection_service.close()


# Create FastAPI app with safe settings loading
def create_app() -> FastAPI:
    """Create FastAPI app with error handling"""
    try:
        # Try to get settings, fallback to safe defaults
        try:
            settings = get_settings()
            debug_mode = settings.DEBUG
        except Exception:
            debug_mode = True  # Safe default for development
        
        return FastAPI(
            title="Prompt Shield API - Multi-Tenant",
            description="Real-time prompt injection detection with multi-tenant isolation",
            version="2.0.0",
            docs_url="/docs" if debug_mode else None,
            redoc_url="/redoc" if debug_mode else None,
            lifespan=lifespan,
            contact={
                "name": "Prompt Shield Platform",
                "url": "https://github.com/lioarce01/prompt-shield",
                "email": "lioarce1@gmail.com"
            },
            license_info={
                "name": "MIT",
                "url": "https://opensource.org/licenses/MIT"
            }
        )
    except Exception as e:
        # Fallback app if settings fail completely
        return FastAPI(
            title="Prompt Shield API - Multi-Tenant",
            description="Real-time prompt injection detection with multi-tenant isolation",
            version="2.0.0",
            lifespan=lifespan
        )

app = create_app()

# Note: Socket.IO will be mounted during lifespan startup

# Add middleware with safe settings loading
def setup_middleware(app: FastAPI):
    """Setup middleware with error handling"""
    try:
        settings = get_settings()
        
        # Add security middleware
        if hasattr(settings, 'allowed_hosts_list'):
            app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts_list)
        
        # Add CORS middleware
        cors_origins = ["*"]  # Safe default
        if hasattr(settings, 'cors_origins_list'):
            cors_origins = settings.cors_origins_list
            
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    except Exception as e:
        # Fallback middleware configuration
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

setup_middleware(app)


@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Log requests and collect metrics with tenant context"""
    import uuid
    
    start_time = time.time()
    
    # Generate correlation ID for request tracing
    correlation_id = str(uuid.uuid4())
    request.state.correlation_id = correlation_id
    
    # Process request
    response: Response = await call_next(request)
    
    # Calculate metrics
    process_time = time.time() - start_time
    
    # Get tenant context if available
    tenant_context = {}
    if hasattr(request.state, 'tenant'):
        tenant_context = {
            "tenant_id": str(request.state.tenant.id),
            "tenant_name": request.state.tenant.name
        }
    
    # Record metrics with tenant context
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()
    
    REQUEST_DURATION.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(process_time)
    
    # Enhanced logging with tenant context
    logger.info(
        "Request processed",
        correlation_id=correlation_id,
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        process_time=process_time,
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "unknown"),
        **tenant_context
    )
    
    # Add correlation headers
    response.headers["X-Process-Time"] = str(process_time)
    response.headers["X-Correlation-ID"] = correlation_id
    
    # Add tenant context headers (for debugging)
    if tenant_context:
        response.headers["X-Tenant-ID"] = tenant_context["tenant_id"]
    
    return response


# Include tenant-aware routers
app.include_router(auth_router, prefix='/auth', tags=['Authentication'])
app.include_router(dashboard_router, prefix='/dashboard', tags=['Dashboard'])
app.include_router(detection_router, prefix='/v1', tags=['Detection'])
app.include_router(tenant_management_router, prefix='/tenant', tags=['Tenant Management'])
app.include_router(websocket_admin_router, prefix='/v1/websocket', tags=['WebSocket Management'])
app.include_router(admin_router, prefix='/v1/admin', tags=['Admin'])
app.include_router(webhooks_router, prefix='/v1/webhooks', tags=['Webhooks'])


@app.get("/health")
async def health_check():
    """Health check endpoint without tenant requirement"""
    try:
        # Check detection engine health if available
        detection_health = {"status": "checking"}
        if hasattr(app.state, 'detection_service'):
            detection_service: DetectionService = app.state.detection_service
            detection_health = await detection_service.health_check()
        
        return {
            "status": "healthy",
            "version": "2.0.0",
            "architecture": "multi-tenant",
            "detection_engine": detection_health,
            "database": "connected",
            "features": {
                "tenant_isolation": True,
                "rate_limiting": True,
                "caching": True,
                "analytics": True
            },
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return {
            "status": "unhealthy",
            "version": "2.0.0",
            "error": str(e),
            "timestamp": time.time()
        }


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "Prompt Shield API",
        "version": "2.0.0",
        "architecture": "multi-tenant",
        "description": "Real-time prompt injection detection with tenant isolation",
        "features": [
            "Multi-tenant isolation",
            "Tenant-specific rate limiting", 
            "Tenant-aware caching",
            "Usage analytics per tenant",
            "Real-time WebSocket dashboards",
            "Live threat detection alerts",
            "Periodic metrics broadcasting",
            "Circuit breaker protection",
            "Fallback detection when engines are down"
        ],
        "endpoints": {
            # Authentication
            "register": "/auth/register",
            "login": "/auth/login", 
            "refresh_token": "/auth/refresh",
            "current_user": "/auth/me",
            
            # Dashboard & API Key Management (JWT required)
            "profile": "/dashboard/profile",
            "create_api_key": "/dashboard/api-keys",
            "list_api_keys": "/dashboard/api-keys",
            "revoke_api_key": "/dashboard/api-keys/{key_id}",
            
            # Detection (API key required)
            "detection": "/v1/detect",
            "batch_detection": "/v1/detect/batch",
            
            # WebSocket management (JWT + API key)
            "websocket_status": "/v1/websocket/status",
            "websocket_metrics": "/v1/websocket/metrics",
            
            # System
            "health": "/health",
            "docs": "/docs"
        },
        "websocket": {
            "endpoint": "/socket.io/",
            "authentication": {
                "dual_auth": {
                    "description": "JWT + API Key (recommended for dashboard)",
                    "auth_object": {"jwt_token": "Bearer eyJ...", "api_key": "pid_abc123..."},
                    "permissions": "Full dashboard access, admin features if admin role"
                },
                "legacy_auth": {
                    "description": "API Key only (backward compatible)", 
                    "auth_object": {"api_key": "pid_abc123..."},
                    "permissions": "Basic metrics and detection events"
                }
            },
            "events": {
                "connection": ["connected", "disconnected"],
                "stats": ["initial_stats", "stats_update", "global_stats"],
                "detections": ["new_detection", "threat_alert"],
                "system": ["metrics_update", "error", "rate_limited"]
            },
            "features": {
                "tenant_isolation": True,
                "role_based_permissions": True,
                "rate_limiting": "Per-session with tenant-specific limits",
                "admin_global_view": "Admins receive system-wide metrics"
            }
        },
        "getting_started": {
            "step_1": "Register account at /auth/register with email/password", 
            "step_2": "Login at /auth/login to get JWT access token",
            "step_3": "Generate API key at /dashboard/api-keys (JWT required)",
            "step_4": "Use API key for detection at /v1/detect",
            "step_5": "Connect to WebSocket with JWT + API key for real-time dashboard"
        },
        "websocket_examples": {
            "dual_auth_js": "const socket = io('/socket.io/', { auth: { jwt_token: 'Bearer JWT...', api_key: 'pid_...' } });",
            "legacy_auth_js": "const socket = io('/socket.io/', { auth: { api_key: 'pid_...' } });",
            "admin_features": "Dual auth with admin role receives global_stats event",
            "rate_limits": "Dual auth: 60 events/min, Legacy: 30 events/min"
        },
        "authentication": {
            "jwt_required": ["Dashboard access", "API key generation", "WebSocket management"],
            "api_key_required": ["Detection requests", "WebSocket data access"],
            "admin_role": ["User management", "Global metrics", "System administration"]
        }
    }


@app.get("/system/status")
async def system_status():
    """Detailed system status for monitoring"""
    try:
        # Get detection engine status
        detection_status = {"status": "unknown"}
        model_status = {"available_models": 0}
        
        if hasattr(app.state, 'detection_service'):
            detection_service: DetectionService = app.state.detection_service
            detection_status = await detection_service.health_check()
            model_status = await detection_service.get_model_status()
        
        # Count active tenants
        from app.core.database import get_db_session
        from app.models.tenant import Tenant
        from sqlalchemy import func, select
        
        async with get_db_session() as db:
            query = select(func.count(Tenant.id)).where(Tenant.status == 'active')
            result = await db.execute(query)
            active_tenants = result.scalar()
        
        return {
            "system": {
                "status": "operational",
                "version": "2.0.0",
                "uptime_seconds": time.time() - app.state.start_time if hasattr(app.state, 'start_time') else 0
            },
            "tenants": {
                "active_count": active_tenants,
                "isolation": "enabled"
            },
            "detection_engine": {
                "status": detection_status.get("status"),
                "available_models": model_status.get("available_models", 0),
                "fallback_available": True
            },
            "database": {
                "status": "connected",
                "schema_version": "2.0"
            },
            "caching": {
                "status": "enabled",
                "type": "redis_per_tenant"
            }
        }
        
    except Exception as e:
        logger.error("System status check failed", error=str(e))
        return {
            "system": {
                "status": "degraded",
                "error": str(e)
            }
        }


# Store startup time for uptime calculation
@app.on_event("startup")
async def startup_event():
    app.state.start_time = time.time()


if __name__ == "__main__":
    import uvicorn
    
    # Safe settings loading for local development
    try:
        settings = get_settings()
        debug_mode = settings.DEBUG
    except Exception:
        debug_mode = True  # Safe default for development
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=debug_mode,
        log_level="info"
    )