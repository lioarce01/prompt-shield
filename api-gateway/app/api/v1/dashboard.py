"""
Dashboard & API Key Management Endpoints
JWT-protected endpoints for user dashboard and API key management
"""

import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.core.rbac import require_authentication, require_admin, check_api_key_generation
from app.core.tenant_auth import tenant_auth
from app.models.tenant import Tenant, TenantAPIKey
from app.services.tenant_analytics_service import TenantAnalyticsService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])
logger = logging.getLogger(__name__)

# Request/Response Models
class CreateAPIKeyRequest(BaseModel):
    """Request to create a new API key"""
    name: Optional[str] = Field(default="Primary API Key", max_length=255, description="API key name")
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "Production API Key"
            }
        }

class APIKeyResponse(BaseModel):
    """API key information"""
    id: str = Field(..., description="API key ID")
    name: str = Field(..., description="API key name")
    key_prefix: str = Field(..., description="Key prefix (pid_12345678)")
    created_at: str = Field(..., description="Creation timestamp")
    last_used_at: Optional[str] = Field(None, description="Last used timestamp")
    is_active: bool = Field(..., description="Whether key is active")

class CreateAPIKeyResponse(BaseModel):
    """Response when creating API key"""
    success: bool = Field(default=True)
    api_key: str = Field(..., description="Full API key (shown only once)")
    key_info: APIKeyResponse = Field(..., description="Key metadata")
    message: str = Field(..., description="Success message")
    warning: str = Field(..., description="Security warning")

class ProfileResponse(BaseModel):
    """User profile information"""
    tenant_id: str = Field(..., description="User/Tenant ID")
    name: str = Field(..., description="Full name")
    email: str = Field(..., description="Email address")
    company: Optional[str] = Field(None, description="Company name")
    role: str = Field(..., description="User role")
    status: str = Field(..., description="Account status")
    is_verified: bool = Field(..., description="Email verification status")
    created_at: str = Field(..., description="Account creation date")
    last_login: Optional[str] = Field(None, description="Last login timestamp")
    
    # API Key status
    has_api_key: bool = Field(..., description="Whether user has API key")
    api_key_created_at: Optional[str] = Field(None, description="API key creation date")
    
    # Settings
    settings: Dict[str, Any] = Field(..., description="Account settings")

class UsageSummaryResponse(BaseModel):
    """Usage analytics summary"""
    tenant_id: str = Field(..., description="User/Tenant ID")
    period: str = Field(..., description="Analytics period")
    
    # Request metrics
    total_requests: int = Field(..., description="Total requests")
    requests_today: int = Field(..., description="Requests today")
    requests_this_week: int = Field(..., description="Requests this week")
    
    # Threat metrics
    threats_blocked: int = Field(..., description="Total threats blocked")
    threats_today: int = Field(..., description="Threats blocked today")
    block_rate: float = Field(..., description="Overall block rate %")
    
    # Performance metrics
    avg_response_time_ms: float = Field(..., description="Average response time")
    cache_hit_rate: float = Field(..., description="Cache hit rate %")
    
    # Top threat types
    top_threat_types: List[Dict[str, Any]] = Field(..., description="Most common threat types")

@router.get("/profile", response_model=ProfileResponse)
async def get_profile(
    current_user: Tenant = Depends(require_authentication),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user profile information
    Requires JWT authentication
    """
    try:
        # Get API key info if exists
        api_key_info = None
        if current_user.api_key:
            api_key_info = {
                "created_at": current_user.api_key.created_at.isoformat(),
                "last_used_at": current_user.api_key.last_used_at.isoformat() if current_user.api_key.last_used_at else None
            }
        
        return ProfileResponse(
            tenant_id=str(current_user.id),
            name=current_user.name,
            email=current_user.email,
            company=current_user.company_name,
            role=current_user.role,
            status=current_user.status,
            is_verified=current_user.is_email_verified,
            created_at=current_user.created_at.isoformat(),
            last_login=current_user.last_login.isoformat() if current_user.last_login else None,
            has_api_key=current_user.api_key is not None,
            api_key_created_at=api_key_info["created_at"] if api_key_info else None,
            settings=current_user.settings
        )
        
    except Exception as e:
        logger.error("Failed to get profile", tenant_id=str(current_user.id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve profile"
        )

@router.post("/api-keys", response_model=CreateAPIKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    request: CreateAPIKeyRequest,
    current_user: Tenant = Depends(require_authentication),
    db: AsyncSession = Depends(get_db)
):
    """
    Create API key for authenticated user
    Each user can have only one API key
    """
    try:
        # Check if user can generate API keys
        check_api_key_generation(current_user)
        
        # Check if user already has an API key
        if current_user.api_key:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="API key already exists. Revoke existing key first."
            )
        
        # Generate API key
        api_key = tenant_auth.generate_api_key()
        key_hash = tenant_auth.hash_api_key(api_key)
        key_prefix = tenant_auth.get_key_prefix(api_key)
        
        # Create API key record
        api_key_record = TenantAPIKey(
            tenant_id=current_user.id,
            key_prefix=key_prefix,
            key_hash=key_hash,
            name=request.name or "Primary API Key",
            is_active=True
        )
        
        db.add(api_key_record)
        await db.commit()
        await db.refresh(api_key_record)
        
        logger.info("API key created", 
                   tenant_id=str(current_user.id),
                   key_prefix=key_prefix)
        
        return CreateAPIKeyResponse(
            api_key=api_key,
            key_info=APIKeyResponse(
                id=str(api_key_record.id),
                name=api_key_record.name,
                key_prefix=key_prefix,
                created_at=api_key_record.created_at.isoformat(),
                last_used_at=None,
                is_active=True
            ),
            message="API key created successfully! Use this key for detection requests.",
            warning="Store this API key securely. You cannot retrieve it again."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create API key", tenant_id=str(current_user.id), error=str(e))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key"
        )

@router.get("/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(
    current_user: Tenant = Depends(require_authentication)
):
    """
    List user's API keys (currently only one allowed)
    """
    try:
        if not current_user.api_key:
            return []
        
        return [APIKeyResponse(
            id=str(current_user.api_key.id),
            name=current_user.api_key.name,
            key_prefix=current_user.api_key.key_prefix,
            created_at=current_user.api_key.created_at.isoformat(),
            last_used_at=current_user.api_key.last_used_at.isoformat() if current_user.api_key.last_used_at else None,
            is_active=current_user.api_key.is_active
        )]
        
    except Exception as e:
        logger.error("Failed to list API keys", tenant_id=str(current_user.id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve API keys"
        )

@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: UUID,
    current_user: Tenant = Depends(require_authentication),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke (delete) API key
    """
    try:
        # Find the API key
        query = select(TenantAPIKey).where(
            TenantAPIKey.id == key_id,
            TenantAPIKey.tenant_id == current_user.id
        )
        result = await db.execute(query)
        api_key = result.scalar_one_or_none()
        
        if not api_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
        
        # Delete the API key
        await db.delete(api_key)
        await db.commit()
        
        logger.info("API key revoked", 
                   tenant_id=str(current_user.id),
                   key_id=str(key_id))
        
        return {
            "success": True,
            "message": "API key revoked successfully",
            "key_id": str(key_id)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to revoke API key", 
                    tenant_id=str(current_user.id),
                    key_id=str(key_id),
                    error=str(e))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke API key"
        )

@router.get("/usage", response_model=UsageSummaryResponse)
async def get_usage_summary(
    current_user: Tenant = Depends(require_authentication),
    db: AsyncSession = Depends(get_db)
):
    """
    Get usage analytics summary for current user
    """
    try:
        analytics_service = TenantAnalyticsService(db)
        summary = await analytics_service.get_tenant_summary(str(current_user.id))
        
        return UsageSummaryResponse(
            tenant_id=str(current_user.id),
            period="last_30_days",
            total_requests=summary.get("total_requests", 0),
            requests_today=summary.get("requests_today", 0),
            requests_this_week=summary.get("requests_this_week", 0),
            threats_blocked=summary.get("threats_blocked", 0),
            threats_today=summary.get("threats_blocked_today", 0),
            block_rate=summary.get("block_rate", 0.0),
            avg_response_time_ms=summary.get("avg_response_time_ms", 0.0),
            cache_hit_rate=summary.get("cache_hit_rate", 0.0),
            top_threat_types=summary.get("top_threat_types", [])
        )
        
    except Exception as e:
        logger.error("Failed to get usage summary", tenant_id=str(current_user.id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve usage summary"
        )

@router.put("/settings")
async def update_settings(
    settings: Dict[str, Any],
    current_user: Tenant = Depends(require_authentication),
    db: AsyncSession = Depends(get_db)
):
    """
    Update user settings
    """
    try:
        # Validate settings (add validation as needed)
        allowed_settings = {
            'detection_threshold', 'cache_enabled', 
            'webhook_url', 'notification_email'
        }
        
        filtered_settings = {
            k: v for k, v in settings.items() 
            if k in allowed_settings
        }
        
        if not filtered_settings:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid settings provided"
            )
        
        # Update settings
        current_user.update_settings(filtered_settings)
        await db.commit()
        
        logger.info("Settings updated", 
                   tenant_id=str(current_user.id),
                   updated_settings=list(filtered_settings.keys()))
        
        return {
            "success": True,
            "message": "Settings updated successfully",
            "updated_settings": filtered_settings
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to update settings", tenant_id=str(current_user.id), error=str(e))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update settings"
        )