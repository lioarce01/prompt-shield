"""
Redis-based Rate Limiting Middleware

Implements sliding window rate limiting per API key with Redis counters.
Enforces both per-minute and per-day limits with proper HTTP 429 responses.
"""
import time
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple

import structlog
import redis.asyncio as redis
from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import get_settings
from app.core.security import extract_api_key_from_request, hash_api_key
from app.models.auth import APIKey
from sqlalchemy import select
from app.core.database import get_db_session

logger = structlog.get_logger()
settings = get_settings()


class RateLimitExceeded(HTTPException):
    """Custom exception for rate limit exceeded with retry-after"""
    def __init__(self, limit_type: str, limit: int, retry_after: int, reset_time: int):
        detail = {
            "error": "rate_limit_exceeded",
            "message": f"Rate limit exceeded: {limit} requests per {limit_type}",
            "limit": limit,
            "limit_type": limit_type,
            "retry_after": retry_after,
            "reset_time": reset_time
        }
        super().__init__(status_code=429, detail=detail)
        self.retry_after = retry_after
        self.reset_time = reset_time


class RedisRateLimiter:
    """Redis-based rate limiter with sliding window implementation"""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        
    async def check_rate_limit(
        self, 
        api_key_id: str, 
        minute_limit: int, 
        day_limit: int
    ) -> Tuple[bool, Optional[RateLimitExceeded]]:
        """
        Check if API key is within rate limits using Redis sliding window
        
        Returns:
            (is_allowed, exception_if_exceeded)
        """
        now = datetime.utcnow()
        current_minute = now.replace(second=0, microsecond=0)
        current_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        # Redis keys for rate limiting
        minute_key = f"rate_limit:{api_key_id}:minute:{int(current_minute.timestamp())}"
        day_key = f"rate_limit:{api_key_id}:day:{int(current_day.timestamp())}"
        
        try:
            # Increment counters FIRST (atomic increment-then-check)
            pipe = self.redis.pipeline()
            pipe.incr(minute_key)
            pipe.expire(minute_key, 60)  # Expire after 1 minute
            pipe.incr(day_key) 
            pipe.expire(day_key, 86400)  # Expire after 1 day
            results = await pipe.execute()
            
            # Get the new counts after increment
            minute_count = int(results[0])  # Result of INCR minute_key
            day_count = int(results[2])     # Result of INCR day_key
            
            # Check minute limit (AFTER incrementing)
            if minute_count > minute_limit:
                # Smart Retry-After calculation optimized for production load
                seconds_until_next_minute = 60 - now.second
                
                # Aggressive short retry times for better UX and performance
                excess_requests = minute_count - minute_limit
                if excess_requests <= 10:
                    # Light overage: very short retry (1-3 seconds)
                    retry_after = min(3, max(1, excess_requests // 3 + 1))
                elif excess_requests <= 30:
                    # Moderate overage: short retry (3-8 seconds)
                    retry_after = min(8, max(3, excess_requests // 5 + 2))
                else:
                    # Heavy overage: medium retry but still reasonable (8-15 seconds)
                    retry_after = min(15, max(8, excess_requests // 10 + 5))
                
                # Add jitter to prevent thundering herd (±30% for more distribution)
                import random
                jitter = random.uniform(0.7, 1.3)
                retry_after = max(1, int(retry_after * jitter))  # Never less than 1 second
                
                reset_time = int((current_minute + timedelta(minutes=1)).timestamp())
                
                logger.warning(
                    "Rate limit exceeded - per minute",
                    api_key_id=api_key_id,
                    current_count=minute_count,
                    limit=minute_limit,
                    excess_requests=excess_requests,
                    retry_after=retry_after,
                    seconds_until_reset=seconds_until_next_minute
                )
                
                return False, RateLimitExceeded(
                    limit_type="minute",
                    limit=minute_limit,
                    retry_after=retry_after,
                    reset_time=reset_time
                )
            
            # Check day limit (AFTER incrementing)
            if day_count > day_limit:
                # For daily limits, use more reasonable retry times
                excess_daily = day_count - day_limit
                
                # Progressive daily backoff (much shorter than full day)
                if excess_daily <= 50:
                    retry_after = 300  # 5 minutes for light daily overage
                elif excess_daily <= 200:
                    retry_after = 900  # 15 minutes for moderate daily overage
                else:
                    retry_after = 1800  # 30 minutes for heavy daily overage
                
                # Add jitter for daily limits too
                import random
                jitter = random.uniform(0.8, 1.2)
                retry_after = int(retry_after * jitter)
                
                reset_time = int((current_day + timedelta(days=1)).timestamp())
                
                logger.warning(
                    "Rate limit exceeded - per day",
                    api_key_id=api_key_id,
                    current_count=day_count,
                    limit=day_limit,
                    excess_requests=excess_daily,
                    retry_after=retry_after,
                    hours_until_reset=int((reset_time - time.time()) / 3600)
                )
                
                return False, RateLimitExceeded(
                    limit_type="day", 
                    limit=day_limit,
                    retry_after=retry_after,
                    reset_time=reset_time
                )
            
            # If we reach here, request is allowed
            
            # Log successful rate limit check
            logger.debug(
                "Rate limit check passed",
                api_key_id=api_key_id,
                minute_count=minute_count + 1,
                minute_limit=minute_limit,
                day_count=day_count + 1,
                day_limit=day_limit
            )
            
            return True, None
            
        except Exception as e:
            logger.error(
                "Rate limiting error - allowing request",
                api_key_id=api_key_id,
                error=str(e)
            )
            # On Redis errors, allow request (fail open)
            return True, None
    
    async def get_current_usage(
        self, 
        api_key_id: str
    ) -> Dict[str, int]:
        """Get current usage counts for an API key"""
        now = datetime.utcnow()
        current_minute = now.replace(second=0, microsecond=0)
        current_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        minute_key = f"rate_limit:{api_key_id}:minute:{int(current_minute.timestamp())}"
        day_key = f"rate_limit:{api_key_id}:day:{int(current_day.timestamp())}"
        
        try:
            pipe = self.redis.pipeline()
            pipe.get(minute_key)
            pipe.get(day_key)
            results = await pipe.execute()
            
            return {
                "requests_this_minute": int(results[0] or 0),
                "requests_today": int(results[1] or 0)
            }
        except Exception as e:
            logger.error("Error getting usage counts", error=str(e))
            return {"requests_this_minute": 0, "requests_today": 0}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for rate limiting"""
    
    def __init__(self, app, redis_client: redis.Redis):
        super().__init__(app)
        self.rate_limiter = RedisRateLimiter(redis_client)
        
        # Paths that should be rate limited
        self.rate_limited_paths = {
            "/v1/detect",
            "/v1/detect/batch", 
            "/v1/detect/async"
        }
        
        # Paths that should skip rate limiting
        self.exempt_paths = {
            "/health",
            "/docs",
            "/openapi.json",
            "/auth/register"  # Allow registration without rate limits
        }
    
    async def dispatch(self, request: Request, call_next):
        """Process request through rate limiting"""
        
        # Skip rate limiting for exempt paths
        if any(request.url.path.startswith(path) for path in self.exempt_paths):
            return await call_next(request)
        
        # Only apply rate limiting to detection endpoints
        if not any(request.url.path.startswith(path) for path in self.rate_limited_paths):
            return await call_next(request)
        
        # Extract API key
        api_key = extract_api_key_from_request(request)
        if not api_key:
            # Let authentication middleware handle this
            return await call_next(request)
        
        # Get API key limits from database
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
                    # Let authentication middleware handle this
                    return await call_next(request)
                
                api_key_id = str(db_api_key.id)
                minute_limit = db_api_key.rate_limit_per_minute
                day_limit = db_api_key.rate_limit_per_day
                
        except Exception as e:
            logger.error("Error checking API key for rate limiting", error=str(e))
            # On database errors, proceed without rate limiting
            return await call_next(request)
        
        # Check rate limits
        is_allowed, rate_limit_error = await self.rate_limiter.check_rate_limit(
            api_key_id, minute_limit, day_limit
        )
        
        if not is_allowed:
            # Add rate limit headers to error response
            response = Response(
                content=rate_limit_error.detail,
                status_code=429,
                media_type="application/json"
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
            usage = await self.rate_limiter.get_current_usage(api_key_id)
            response.headers["X-RateLimit-Limit-Minute"] = str(minute_limit)
            response.headers["X-RateLimit-Remaining-Minute"] = str(max(0, minute_limit - usage["requests_this_minute"]))
            response.headers["X-RateLimit-Limit-Day"] = str(day_limit)
            response.headers["X-RateLimit-Remaining-Day"] = str(max(0, day_limit - usage["requests_today"]))
        except Exception as e:
            logger.error("Error adding rate limit headers", error=str(e))
        
        return response


async def get_redis_client() -> redis.Redis:
    """Get Redis client for rate limiting"""
    # Use REDIS_URL if available (Docker), otherwise use individual host/port (local dev)
    if hasattr(settings, 'REDIS_URL') and settings.REDIS_URL:
        # Parse Redis URL for connection
        return redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True
        )
    else:
        # Fallback to host/port configuration
        return redis.Redis(
            host=getattr(settings, 'REDIS_HOST', 'localhost'),
            port=getattr(settings, 'REDIS_PORT', 6379),
            db=getattr(settings, 'REDIS_DB_RATE_LIMIT', 0),
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True
        )