"""
FastAPI Gateway for Prompt Injection Defense Platform

Provides enterprise-ready access to the Go detection engine with:
- API key authentication and rate limiting
- Usage analytics and webhook delivery
- Developer-friendly documentation and SDKs
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

from app.api.v1 import detection, auth, webhooks, admin
from app.core.config import get_settings
from app.core.database import init_db
from app.core.openapi import customize_openapi_schema, get_openapi_tags
from app.services.detection_client import DetectionClient
# Import models so SQLAlchemy can create tables
from app.models import auth as auth_models

# Prometheus metrics
REQUEST_COUNT = Counter('api_requests_total', 'Total API requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('api_request_duration_seconds', 'Request duration', ['method', 'endpoint'])

settings = get_settings()

# Configure structured logging
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
    # Startup
    logger.info("Starting API Gateway", version=settings.VERSION)
    
    # Initialize database
    await init_db()
    
    # Initialize detection client
    detection_client = DetectionClient(settings.DETECTION_ENGINE_URL)
    app.state.detection_client = detection_client
    
    # Test connection to Go detection engine
    try:
        health = await detection_client.health_check()
        logger.info("Detection engine connected", status=health.get("status"))
    except Exception as e:
        logger.error("Failed to connect to detection engine", error=str(e))
    
    yield
    
    # Shutdown
    logger.info("Shutting down API Gateway")
    if hasattr(app.state, 'detection_client'):
        await app.state.detection_client.close()


# Create FastAPI app
app = FastAPI(
    title="Prompt Injection Defense API",
    description="Real-time prompt injection detection with <50ms latency",
    version=settings.VERSION,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_tags=get_openapi_tags(),
    lifespan=lifespan,
    contact={
        "name": "Prompt Injection Defense Platform",
        "url": "https://github.com/lioarce01/prompt-shield",
        "email": "lioarce1@gmail.com"
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT"
    }
)

# Add security middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Log requests and collect metrics"""
    start_time = time.time()
    
    # Process request
    response: Response = await call_next(request)
    
    # Calculate metrics
    process_time = time.time() - start_time
    
    # Record metrics
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()
    
    REQUEST_DURATION.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(process_time)
    
    # Log request
    logger.info(
        "Request processed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        process_time=process_time,
        client_ip=request.client.host if request.client else None
    )
    
    # Add timing header
    response.headers["X-Process-Time"] = str(process_time)
    
    return response


# Include API routers
app.include_router(detection.router, prefix="/v1", tags=["Detection"])
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(webhooks.router, prefix="/webhooks", tags=["Webhooks"])
app.include_router(admin.router, prefix="/admin", tags=["Admin"])


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check detection engine health
        detection_client: DetectionClient = app.state.detection_client
        detection_health = await detection_client.health_check()
        
        return {
            "status": "healthy",
            "version": settings.VERSION,
            "detection_engine": detection_health,
            "timestamp": time.time()
        }
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return {
            "status": "unhealthy",
            "version": settings.VERSION,
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
        "name": "Prompt Injection Defense API",
        "version": settings.VERSION,
        "description": "Real-time prompt injection detection with <50ms latency",
        "docs": "/docs" if settings.DEBUG else None,
        "health": "/health",
        "metrics": "/metrics"
    }


# Customize OpenAPI schema
app.openapi = lambda: customize_openapi_schema(app)


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )