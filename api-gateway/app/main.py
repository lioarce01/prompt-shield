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
from app.middleware.rate_limiter import RateLimitMiddleware, get_redis_client
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
    
    # Initialize Redis client for rate limiting
    try:
        redis_client = await get_redis_client()
        app.state.redis_client = redis_client
        logger.info("Redis connected for rate limiting")
    except Exception as e:
        logger.error("Failed to connect to Redis", error=str(e))
    
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
    if hasattr(app.state, 'redis_client'):
        await app.state.redis_client.close()


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
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts_list)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting middleware
@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    """Rate limiting middleware using Redis"""
    from app.middleware.rate_limiter import RedisRateLimiter
    from app.core.security import extract_api_key_from_request, hash_api_key
    from app.models.auth import APIKey
    from sqlalchemy import select
    from app.core.database import get_db_session
    
    # Check if this path needs rate limiting
    rate_limited_paths = {"/v1/detect", "/v1/detect/batch", "/v1/detect/async"}
    exempt_paths = {"/health", "/docs", "/openapi.json", "/auth/register"}
    
    should_rate_limit = (
        any(request.url.path.startswith(path) for path in rate_limited_paths) and
        not any(request.url.path.startswith(path) for path in exempt_paths)
    )
    
    if not should_rate_limit or not hasattr(app.state, 'redis_client'):
        return await call_next(request)
    
    # Extract API key and get limits
    api_key = extract_api_key_from_request(request)
    if not api_key:
        return await call_next(request)
    
    try:
        key_hash = hash_api_key(api_key)
        async with get_db_session() as db:
            stmt = select(APIKey).where(
                APIKey.key_hash == key_hash,
                APIKey.is_active == True
            )
            result = await db.execute(stmt)
            db_api_key = result.scalar_one_or_none()
            
            if not db_api_key:
                return await call_next(request)
            
            api_key_id = str(db_api_key.id)
            minute_limit = db_api_key.rate_limit_per_minute
            day_limit = db_api_key.rate_limit_per_day
            
    except Exception as e:
        logger.error("Error checking API key for rate limiting", error=str(e))
        return await call_next(request)
    
    # Check rate limits
    rate_limiter = RedisRateLimiter(app.state.redis_client)
    is_allowed, rate_limit_error = await rate_limiter.check_rate_limit(
        api_key_id, minute_limit, day_limit
    )
    
    if not is_allowed:
        # Return rate limit exceeded error
        from fastapi.responses import JSONResponse
        response = JSONResponse(
            content=rate_limit_error.detail,
            status_code=429
        )
        response.headers["Retry-After"] = str(rate_limit_error.retry_after)
        response.headers["X-RateLimit-Limit-Minute"] = str(minute_limit)
        response.headers["X-RateLimit-Limit-Day"] = str(day_limit)
        response.headers["X-RateLimit-Reset"] = str(rate_limit_error.reset_time)
        return response
    
    # Process request
    response = await call_next(request)
    
    # Add rate limit headers to successful response
    try:
        usage = await rate_limiter.get_current_usage(api_key_id)
        response.headers["X-RateLimit-Limit-Minute"] = str(minute_limit)
        response.headers["X-RateLimit-Remaining-Minute"] = str(max(0, minute_limit - usage["requests_this_minute"]))
        response.headers["X-RateLimit-Limit-Day"] = str(day_limit)
        response.headers["X-RateLimit-Remaining-Day"] = str(max(0, day_limit - usage["requests_today"]))
    except Exception as e:
        logger.error("Error adding rate limit headers", error=str(e))
    
    return response


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