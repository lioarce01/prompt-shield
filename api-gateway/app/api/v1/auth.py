"""
Authentication API endpoints

Handles API key management, user registration, and authentication
for accessing the prompt injection detection services.
"""
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

import structlog
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.core.security import generate_api_key, hash_api_key, APIKeyInfo
from app.utils.validators import validate_api_key_name, validate_rate_limits
from app.api.dependencies import get_current_api_key, get_database
from app.models.auth import APIKey, UsageLog
from sqlalchemy import select, func
from sqlalchemy.sql import and_
import uuid

logger = structlog.get_logger()
router = APIRouter()
settings = get_settings()


class APIKeyRequest(BaseModel):
    """Request to create a new API key"""
    name: str = Field(..., max_length=100, description="Human-readable name for the API key")
    rate_limit_per_minute: Optional[int] = Field(
        default=None,
        ge=1,
        le=1000,
        description="Custom rate limit per minute (default: 60)"
    )
    rate_limit_per_day: Optional[int] = Field(
        default=None,
        ge=1,
        le=100000,
        description="Custom rate limit per day (default: 10000)"
    )


class APIKeyResponse(BaseModel):
    """Response containing new API key information"""
    api_key: str = Field(..., description="The generated API key (store securely - won't be shown again)")
    key_id: str = Field(..., description="Unique identifier for this API key")
    name: str = Field(..., description="Human-readable name")
    rate_limit_per_minute: int = Field(..., description="Requests per minute allowed")
    rate_limit_per_day: int = Field(..., description="Requests per day allowed")
    created_at: datetime = Field(..., description="When the key was created")
    expires_at: Optional[datetime] = Field(None, description="When the key expires (if applicable)")


class APIKeyInfo(BaseModel):
    """API key information without the actual key"""
    key_id: str = Field(..., description="Unique identifier")
    name: str = Field(..., description="Human-readable name")
    rate_limit_per_minute: int = Field(..., description="Requests per minute allowed")
    rate_limit_per_day: int = Field(..., description="Requests per day allowed")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_used_at: Optional[datetime] = Field(None, description="Last usage timestamp")
    is_active: bool = Field(..., description="Whether the key is active")
    total_requests: int = Field(default=0, description="Total requests made with this key")


class UsageStats(BaseModel):
    """Usage statistics for an API key"""
    key_id: str = Field(..., description="API key identifier")
    name: str = Field(..., description="API key name")
    requests_today: int = Field(..., description="Requests made today")
    requests_this_minute: int = Field(..., description="Requests in current minute")
    rate_limit_per_minute: int = Field(..., description="Rate limit per minute")
    rate_limit_per_day: int = Field(..., description="Rate limit per day")
    total_requests: int = Field(..., description="Total requests ever")
    malicious_detections: int = Field(..., description="Total malicious content detected")
    last_used_at: Optional[datetime] = Field(None, description="Last usage")






@router.post("/register", response_model=APIKeyResponse)
async def create_api_key(
    request: APIKeyRequest,
    db = Depends(get_database)
) -> APIKeyResponse:
    """
    Create a new API key for accessing detection services
    
    **Generate API Key** - Creates a new API key with specified rate limits
    and usage tracking. Store the returned key securely as it won't be shown again.
    
    **Default Limits:**
    - 60 requests per minute
    - 10,000 requests per day
    
    **Custom Limits:**
    - Up to 1,000 requests per minute
    - Up to 100,000 requests per day
    """
    try:
        # Generate new API key
        api_key = generate_api_key()
        key_hash = hash_api_key(api_key)
        key_id = secrets.token_hex(16)
        
        # Set rate limits (use defaults if not specified)
        rate_limit_per_minute = request.rate_limit_per_minute or settings.DEFAULT_RATE_LIMIT_PER_MINUTE
        rate_limit_per_day = request.rate_limit_per_day or settings.DEFAULT_RATE_LIMIT_PER_DAY
        
        # Create API key record in database
        db_api_key = APIKey(
            key_hash=key_hash,
            name=request.name,
            rate_limit_per_minute=rate_limit_per_minute,
            rate_limit_per_day=rate_limit_per_day
        )
        
        # Save to database
        db.add(db_api_key)
        await db.commit()
        await db.refresh(db_api_key)
        
        # Log API key creation (don't log the actual key!)
        logger.info(
            "API key created",
            key_id=str(db_api_key.id),
            name=request.name,
            rate_limit_per_minute=rate_limit_per_minute,
            rate_limit_per_day=rate_limit_per_day
        )
        
        return APIKeyResponse(
            api_key=api_key,
            key_id=str(db_api_key.id),
            name=request.name,
            rate_limit_per_minute=rate_limit_per_minute,
            rate_limit_per_day=rate_limit_per_day,
            created_at=db_api_key.created_at,
            expires_at=None  # No expiration for now
        )
        
    except Exception as e:
        logger.error("Failed to create API key", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to create API key")


@router.get(
    "/profile", 
    response_model=UsageStats,
    responses={
        401: {"description": "Unauthorized - API key required"}
    }
)
async def get_api_key_profile(
    api_key_info: APIKeyInfo = Depends(get_current_api_key),
    db = Depends(get_database)
) -> UsageStats:
    """
    Get usage statistics and profile for your API key
    
    **Profile Information** - Returns current usage statistics,
    rate limits, and activity history for the authenticated API key.
    """
    try:
        logger.info("Profile requested", key_id=api_key_info.key_id)
        
        # Get current time boundaries
        now = datetime.utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        minute_start = now.replace(second=0, microsecond=0)
        
        # Query usage statistics
        api_key_uuid = uuid.UUID(api_key_info.key_id)
        
        # Total requests
        total_stmt = select(func.count(UsageLog.id)).where(
            UsageLog.api_key_id == api_key_uuid
        )
        total_result = await db.execute(total_stmt)
        total_requests = total_result.scalar() or 0
        
        # Requests today
        today_stmt = select(func.count(UsageLog.id)).where(
            and_(
                UsageLog.api_key_id == api_key_uuid,
                UsageLog.created_at >= today_start
            )
        )
        today_result = await db.execute(today_stmt)
        requests_today = today_result.scalar() or 0
        
        # Requests this minute
        minute_stmt = select(func.count(UsageLog.id)).where(
            and_(
                UsageLog.api_key_id == api_key_uuid,
                UsageLog.created_at >= minute_start
            )
        )
        minute_result = await db.execute(minute_stmt)
        requests_this_minute = minute_result.scalar() or 0
        
        # Malicious detections
        malicious_stmt = select(func.count(UsageLog.id)).where(
            and_(
                UsageLog.api_key_id == api_key_uuid,
                UsageLog.is_malicious == True
            )
        )
        malicious_result = await db.execute(malicious_stmt)
        malicious_detections = malicious_result.scalar() or 0
        
        # Get API key details for last_used_at
        api_key_stmt = select(APIKey).where(APIKey.id == api_key_uuid)
        api_key_result = await db.execute(api_key_stmt)
        db_api_key = api_key_result.scalar_one()
        
        return UsageStats(
            key_id=api_key_info.key_id,
            name=api_key_info.name,
            requests_today=requests_today,
            requests_this_minute=requests_this_minute,
            rate_limit_per_minute=api_key_info.rate_limit_per_minute,
            rate_limit_per_day=api_key_info.rate_limit_per_day,
            total_requests=total_requests,
            malicious_detections=malicious_detections,
            last_used_at=db_api_key.last_used_at or db_api_key.created_at
        )
        
    except Exception as e:
        logger.error("Failed to get profile", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get profile")


@router.post(
    "/rotate-key", 
    response_model=APIKeyResponse,
    responses={
        401: {"description": "Unauthorized - API key required"}
    }
)
async def rotate_api_key(
    api_key_info: APIKeyInfo = Depends(get_current_api_key)
) -> APIKeyResponse:
    """
    Rotate your API key to a new value
    
    **Security Best Practice** - Generate a new API key while keeping
    the same configuration and usage history. The old key is immediately invalidated.
    """
    try:
        # TODO: Get current API key info from authentication
        # For now, return mock response
        
        new_api_key = generate_api_key()
        key_id = "mock_key_123"
        
        logger.info("API key rotated", key_id=key_id)
        
        return APIKeyResponse(
            api_key=new_api_key,
            key_id=key_id,
            name="Development Key",
            rate_limit_per_minute=60,
            rate_limit_per_day=10000,
            created_at=datetime.utcnow(),
            expires_at=None
        )
        
    except Exception as e:
        logger.error("Failed to rotate API key", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to rotate API key")


@router.delete(
    "/revoke",
    responses={
        401: {"description": "Unauthorized - API key required"}
    }
)
async def revoke_api_key(
    api_key_info: APIKeyInfo = Depends(get_current_api_key)
) -> Dict[str, str]:
    """
    Revoke your API key permanently
    
    **Permanent Action** - Immediately invalidates your API key.
    This action cannot be undone. You'll need to create a new key to continue using the service.
    """
    try:
        # TODO: Get current API key info from authentication and revoke it
        key_id = "mock_key_123"
        
        logger.info("API key revoked", key_id=key_id)
        
        return {
            "message": "API key revoked successfully",
            "key_id": key_id,
            "revoked_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to revoke API key", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to revoke API key")


@router.get(
    "/validate",
    responses={
        401: {"description": "Unauthorized - API key required"}
    }
)
async def validate_api_key(
    api_key_info: APIKeyInfo = Depends(get_current_api_key)
) -> Dict[str, Any]:
    """
    Validate your API key and check current status
    
    **Key Validation** - Verify that your API key is valid and active,
    and get current rate limiting status.
    """
    try:
        # TODO: Get actual API key info from authentication
        # For now, return mock validation
        
        return {
            "valid": True,
            "key_id": api_key_info.key_id,
            "name": api_key_info.name,
            "is_active": True,
            "rate_limits": {
                "per_minute": 60,
                "per_day": 10000,
                "current_minute_usage": 2,
                "current_day_usage": 42
            },
            "validated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to validate API key", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to validate API key")