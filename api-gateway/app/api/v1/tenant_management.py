"""
Tenant Management API Endpoints
Clean implementation for multi-tenant architecture
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from pydantic import EmailStr, Field, field_validator
from app.core.base_model import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime, timedelta, date
from sqlalchemy import func, and_

from app.core.database import get_db
from app.models.tenant import Tenant, TenantAPIKey, TenantUsageDaily
from app.core.tenant_auth import tenant_auth, get_current_tenant

router = APIRouter(prefix="/tenant", tags=["Tenant Management"])


# ===================================================
# PYDANTIC SCHEMAS
# ===================================================

class TenantRegistration(BaseModel):
    """Schema for tenant registration"""
    name: str = Field(..., min_length=1, max_length=255, description="Contact person name")
    email: EmailStr = Field(..., description="Primary contact email")
    company_name: Optional[str] = Field(None, max_length=255, description="Company name (optional)")
    
    @field_validator('name')
    @classmethod
    def name_must_not_be_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Name cannot be empty')
        return v.strip()
    
    @field_validator('company_name')
    @classmethod
    def company_name_optional(cls, v):
        return v.strip() if v else None


class TenantResponse(BaseModel):
    """Schema for tenant information response"""
    tenant_id: str
    name: str
    email: str
    company_name: Optional[str]
    status: str
    created_at: datetime
    api_key_prefix: str  # Only show prefix, never full key
    settings: Dict[str, Any]
    


class TenantSettings(BaseModel):
    """Schema for updating tenant settings"""
    detection_threshold: Optional[float] = Field(None, ge=0.0, le=1.0)
    rate_limit_per_minute: Optional[int] = Field(None, gt=0, le=10000)
    cache_enabled: Optional[bool] = None
    webhook_url: Optional[str] = Field(None, pattern=r'^https?://.+')
    notification_email: Optional[EmailStr] = None


class UsageSummary(BaseModel):
    """Schema for usage summary response"""
    period_days: int
    total_requests: int
    malicious_blocked: int
    safe_allowed: int
    block_rate_percentage: float
    avg_processing_time_ms: float
    cache_hit_rate_percentage: float


# ===================================================
# TENANT REGISTRATION & MANAGEMENT
# ===================================================

@router.post("/register", response_model=dict)
async def register_tenant(
    registration: TenantRegistration,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new tenant and generate single API key
    
    Creates:
    - New tenant record
    - Single API key for the tenant
    - Initial settings configuration
    
    Returns API key ONLY ONCE - it won't be shown again!
    """
    
    # Check if email already exists
    result = await db.execute(select(Tenant).where(Tenant.email == registration.email))
    existing_tenant = result.scalar_one_or_none()
    if existing_tenant:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Tenant with email {registration.email} already exists"
        )
    
    try:
        # Create tenant (no API key yet)
        tenant = Tenant(
            name=registration.name,
            email=registration.email,
            company_name=registration.company_name,
            status='active',
            settings={
                "detection_threshold": 0.7,
                "rate_limit_per_minute": 1000,
                "cache_enabled": True,
                "webhook_url": None,
                "notification_email": registration.email
            }
        )
        db.add(tenant)
        await db.commit()
        
        return {
            "success": True,
            "tenant_id": str(tenant.id),
            "tenant_name": tenant.name,
            "email": tenant.email,
            "company_name": tenant.company_name,
            "status": tenant.status,
            "created_at": tenant.created_at,
            "message": "🎉 Tenant registered successfully! Now create your API key.",
            "next_steps": [
                "Create your API key using POST /tenant/api-key/create",
                "Save your API key in a secure location",
                "Test the API key with a sample request",
                "Configure your detection threshold if needed"
            ]
        }
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to register tenant: {str(e)}"
        )


@router.get("/profile", response_model=TenantResponse)
async def get_tenant_profile(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """Get current tenant profile and configuration"""
    
    # Get API key info
    result = await db.execute(select(TenantAPIKey).where(TenantAPIKey.tenant_id == tenant.id))
    api_key = result.scalar_one_or_none()
    
    return TenantResponse(
        tenant_id=str(tenant.id),
        name=tenant.name,
        email=tenant.email,
        company_name=tenant.company_name,
        status=tenant.status,
        created_at=tenant.created_at,
        api_key_prefix=api_key.key_prefix if api_key else "N/A",
        settings=tenant.settings
    )


@router.put("/settings")
async def update_tenant_settings(
    settings_update: TenantSettings,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """Update tenant-specific settings"""
    
    # Update only provided settings
    update_data = settings_update.dict(exclude_unset=True)
    
    if update_data:
        tenant.update_settings(update_data)
        await db.commit()
        
        return {
            "success": True,
            "message": "Settings updated successfully",
            "updated_settings": update_data,
            "current_settings": tenant.settings
        }
    
    return {
        "success": False,
        "message": "No settings provided to update"
    }


# ===================================================
# USAGE ANALYTICS
# ===================================================

@router.get("/usage/summary")
async def get_usage_summary(
    days: int = Query(default=30, ge=1, le=365, description="Number of days to analyze"),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """Get tenant usage summary for specified period"""
    
    end_date = date.today()
    start_date = end_date - timedelta(days=days)
    
    # Get aggregated usage data
    query = select(TenantUsageDaily).where(
        and_(
            TenantUsageDaily.tenant_id == tenant.id,
            TenantUsageDaily.date >= start_date,
            TenantUsageDaily.date <= end_date
        )
    )
    result = await db.execute(query)
    usage_data = result.scalars().all()
    
    if not usage_data:
        return {
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "days": days
            },
            "summary": {
                "total_requests": 0,
                "malicious_blocked": 0,
                "safe_allowed": 0,
                "block_rate_percentage": 0,
                "avg_processing_time_ms": 0,
                "cache_hit_rate_percentage": 0
            },
            "message": f"No usage data found for the last {days} days"
        }
    
    # Calculate totals
    total_requests = sum(u.total_requests for u in usage_data)
    total_blocked = sum(u.malicious_requests for u in usage_data)
    total_allowed = sum(u.safe_requests for u in usage_data)
    total_cache_hits = sum(u.cache_hits for u in usage_data)
    # Note: cache_misses not available in current schema
    total_cache_misses = 0
    
    # Calculate weighted averages
    total_processing_time = sum(u.avg_processing_time_ms * u.total_requests for u in usage_data)
    avg_processing_time = total_processing_time / total_requests if total_requests > 0 else 0
    
    cache_total = total_cache_hits + total_cache_misses
    cache_hit_rate = (total_cache_hits / cache_total * 100) if cache_total > 0 else 0
    
    block_rate = (total_blocked / total_requests * 100) if total_requests > 0 else 0
    
    return {
        "tenant_info": {
            "tenant_id": str(tenant.id),
            "tenant_name": tenant.name
        },
        "period": {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "days": days
        },
        "summary": {
            "total_requests": total_requests,
            "malicious_blocked": total_blocked,
            "safe_allowed": total_allowed,
            "block_rate_percentage": round(block_rate, 2),
            "avg_processing_time_ms": round(avg_processing_time, 2),
            "cache_hit_rate_percentage": round(cache_hit_rate, 2)
        },
        "daily_breakdown": [
            {
                "date": u.date.isoformat(),
                "requests": u.total_requests,
                "blocked": u.malicious_requests,
                "allowed": u.safe_requests,
                "avg_processing_ms": float(u.avg_processing_time_ms),
                "cache_hits": u.cache_hits,
                "cache_misses": 0  # Not available in current schema
            } for u in sorted(usage_data, key=lambda x: x.date, reverse=True)
        ]
    }


@router.get("/usage/recent")
async def get_recent_requests(
    limit: int = Query(default=100, ge=1, le=1000),
    hours: int = Query(default=24, ge=1, le=168),  # Max 1 week
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """Get recent requests for debugging and analysis"""
    
    from app.models.tenant import TenantRequest
    
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    
    query = select(TenantRequest).where(
        and_(
            TenantRequest.tenant_id == tenant.id,
            TenantRequest.created_at >= cutoff_time
        )
    ).order_by(TenantRequest.created_at.desc()).limit(limit)
    result = await db.execute(query)
    recent_requests = result.scalars().all()
    
    return {
        "tenant_id": str(tenant.id),
        "period": {
            "last_hours": hours,
            "from": cutoff_time.isoformat(),
            "to": datetime.utcnow().isoformat()
        },
        "total_found": len(recent_requests),
        "limit": limit,
        "requests": [
            {
                "request_id": req.request_id,
                "timestamp": req.created_at.isoformat(),
                "text_length": req.text_length,
                "is_malicious": req.is_malicious,
                "confidence": float(req.confidence),
                "threat_types": req.threat_types,
                "processing_time_ms": float(req.processing_time_ms),
                "cache_hit": req.cache_hit,
                "model_used": req.model_used
            } for req in recent_requests
        ]
    }


# ===================================================
# API KEY MANAGEMENT
# ===================================================

class APIKeyRequest(BaseModel):
    """Schema for API key creation"""
    tenant_id: str = Field(..., description="Tenant ID from registration")

@router.post("/api-key/create")
async def create_api_key(
    request: APIKeyRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Create first API key for tenant using tenant_id and password
    """
    
    try:
        # Find tenant by ID
        result = await db.execute(select(Tenant).where(Tenant.id == request.tenant_id))
        tenant = result.scalar_one_or_none()
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tenant not found"
            )
        
        # Check if tenant already has an API key
        result = await db.execute(select(TenantAPIKey).where(TenantAPIKey.tenant_id == tenant.id))
        existing_key = result.scalar_one_or_none()
        if existing_key:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Tenant already has an API key. Use regenerate endpoint instead."
            )
        
        # Generate API key
        api_key_plain = tenant_auth.generate_api_key()
        api_key_hash = tenant_auth.hash_api_key(api_key_plain)
        key_prefix = tenant_auth.get_key_prefix(api_key_plain)
        
        # Create API key record
        api_key_record = TenantAPIKey(
            tenant_id=tenant.id,
            key_prefix=key_prefix,
            key_hash=api_key_hash,
            name=f"{tenant.name} - Primary API Key"
        )
        db.add(api_key_record)
        await db.commit()
        
        return {
            "success": True,
            "tenant_id": str(tenant.id),
            "api_key": api_key_plain,  # ⚠️ ONLY SHOWN ONCE!
            "api_key_prefix": key_prefix,
            "created_at": api_key_record.created_at,
            "message": "🎉 API key created successfully! Save it - it won't be shown again.",
            "warning": "Store this API key securely. You cannot retrieve it again."
        }
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create API key: {str(e)}"
        )


@router.post("/api-key/regenerate")
async def regenerate_api_key(
    confirmation: str = Query(default="", description="Type 'REGENERATE' to confirm"),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """
    Regenerate API key for tenant
    ⚠️ This will invalidate the current API key immediately!
    """
    
    if confirmation != "REGENERATE":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please confirm by setting confirmation='REGENERATE'"
        )
    
    try:
        # Get current API key
        result = await db.execute(select(TenantAPIKey).where(TenantAPIKey.tenant_id == tenant.id))
        current_key = result.scalar_one_or_none()
        
        if not current_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No API key found for tenant"
            )
        
        # Generate new API key
        new_api_key_plain = tenant_auth.generate_api_key()
        new_api_key_hash = tenant_auth.hash_api_key(new_api_key_plain)
        new_key_prefix = tenant_auth.get_key_prefix(new_api_key_plain)
        
        # Update the existing record
        current_key.key_prefix = new_key_prefix
        current_key.key_hash = new_api_key_hash
        current_key.created_at = datetime.utcnow()
        current_key.last_used_at = None
        
        await db.commit()
        
        return {
            "success": True,
            "message": "⚠️ API key regenerated successfully! Save the new key - it won't be shown again.",
            "new_api_key": new_api_key_plain,  # ⚠️ ONLY SHOWN ONCE!
            "new_key_prefix": new_key_prefix,
            "regenerated_at": current_key.created_at,
            "warning": "Your old API key is now invalid. Update all applications immediately."
        }
        
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to regenerate API key: {str(e)}"
        )


# ===================================================
# TENANT STATUS AND HEALTH
# ===================================================

@router.get("/status")
async def get_tenant_status(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db)
):
    """Get comprehensive tenant status and health information"""
    
    # Get recent usage (last 24 hours)
    yesterday = date.today() - timedelta(days=1)
    query = select(TenantUsageDaily).where(
        and_(
            TenantUsageDaily.tenant_id == tenant.id,
            TenantUsageDaily.date >= yesterday
        )
    )
    result = await db.execute(query)
    recent_usage = result.scalar_one_or_none()
    
    # Get API key info
    result = await db.execute(select(TenantAPIKey).where(TenantAPIKey.tenant_id == tenant.id))
    api_key = result.scalar_one_or_none()
    
    return {
        "tenant": {
            "id": str(tenant.id),
            "name": tenant.name,
            "email": tenant.email,
            "status": tenant.status,
            "created_at": tenant.created_at.isoformat()
        },
        "api_key": {
            "prefix": api_key.key_prefix if api_key else None,
            "last_used": api_key.last_used_at.isoformat() if api_key and api_key.last_used_at else None,
            "is_active": api_key.is_active if api_key else False
        },
        "settings": tenant.settings,
        "recent_activity": {
            "last_24h_requests": recent_usage.total_requests if recent_usage else 0,
            "last_24h_blocked": recent_usage.malicious_requests if recent_usage else 0,
            "avg_processing_time_ms": float(recent_usage.avg_processing_time_ms) if recent_usage else 0
        },
        "limits": {
            "rate_limit_per_minute": tenant.rate_limit_per_minute,
            "detection_threshold": tenant.detection_threshold
        },
        "health": "healthy" if tenant.is_active else "inactive"
    }