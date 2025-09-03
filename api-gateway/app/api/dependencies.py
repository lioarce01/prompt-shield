"""
FastAPI dependencies for authentication and common functionality

Provides reusable dependency functions for API key authentication,
rate limiting, and other common operations.
"""
from fastapi import Depends, HTTPException, Request
from app.core.security import authenticate_api_key, authenticate_admin_key, APIKeyInfo
from app.core.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession


# Export authentication dependencies
async def get_current_api_key(request: Request) -> APIKeyInfo:
    """Get current authenticated API key"""
    return await authenticate_api_key(request)


async def get_admin_api_key(request: Request) -> APIKeyInfo:
    """Get current authenticated admin API key"""
    api_key = await authenticate_api_key(request)
    return await authenticate_admin_key(api_key)


async def get_database() -> AsyncSession:
    """Get database session"""
    async with get_db() as session:
        yield session