"""
FastAPI dependencies for authentication and common functionality

Provides reusable dependency functions for API key authentication,
rate limiting, and other common operations.
"""
import redis
from fastapi import Depends, HTTPException, Request
from app.core.security import authenticate_api_key, authenticate_admin_key, APIKeyInfo
from app.core.database import get_db
from app.core.config import get_settings
from app.services.cache_service import DetectionCacheService
from sqlalchemy.ext.asyncio import AsyncSession


# Export authentication dependencies
async def get_current_api_key(request: Request) -> APIKeyInfo:
    """Get current authenticated API key"""
    return await authenticate_api_key(request)


async def get_admin_api_key(request: Request) -> APIKeyInfo:
    """Get current authenticated admin API key"""
    api_key = await authenticate_api_key(request)
    return await authenticate_admin_key(api_key)


async def get_database():
    """Get database session"""
    async for session in get_db():
        yield session


# Redis client singleton
_redis_client = None

def get_redis_client() -> redis.Redis:
    """Get Redis client (singleton)"""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            max_connections=20
        )
    return _redis_client


# Cache service singleton
_cache_service = None

def get_cache_service() -> DetectionCacheService:
    """Get detection cache service (singleton)"""
    global _cache_service
    if _cache_service is None:
        redis_client = get_redis_client()
        _cache_service = DetectionCacheService(redis_client)
    return _cache_service