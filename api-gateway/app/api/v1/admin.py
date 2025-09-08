"""
Admin Panel Endpoints
Admin-only endpoints for tenant management, global metrics, and system administration
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func, desc, and_, or_
from pydantic import BaseModel, Field, EmailStr

from app.core.database import get_db
from app.core.rbac import require_admin, require_authentication
from app.core.tenant_auth import tenant_auth
from app.models.tenant import Tenant, TenantAPIKey
from app.services.tenant_analytics_service import TenantAnalyticsService

router = APIRouter(prefix="/admin", tags=["Admin Panel"])
logger = logging.getLogger(__name__)

# Request/Response Models
class TenantSummary(BaseModel):
    """Summary of tenant information for admin"""
    id: str = Field(..., description="Tenant ID")
    name: str = Field(..., description="Tenant name")
    email: str = Field(..., description="Email address")
    company_name: Optional[str] = Field(None, description="Company name")
    role: str = Field(..., description="User role")
    status: str = Field(..., description="Account status")
    is_verified: bool = Field(..., description="Email verification status")
    is_authenticated: bool = Field(..., description="Has password set (JWT capable)")
    created_at: str = Field(..., description="Account creation date")
    last_login: Optional[str] = Field(None, description="Last login timestamp")
    
    # API Key info
    has_api_key: bool = Field(..., description="Whether tenant has API key")
    api_key_created_at: Optional[str] = Field(None, description="API key creation date")
    api_key_last_used: Optional[str] = Field(None, description="API key last used")
    
    # Usage stats
    total_requests: int = Field(..., description="Total detection requests")
    requests_last_30_days: int = Field(..., description="Requests in last 30 days")
    threats_blocked: int = Field(..., description="Total threats blocked")

class TenantListResponse(BaseModel):
    """Paginated list of tenants"""
    tenants: List[TenantSummary] = Field(..., description="List of tenants")
    total_count: int = Field(..., description="Total number of tenants")
    page: int = Field(..., description="Current page")
    page_size: int = Field(..., description="Items per page")
    total_pages: int = Field(..., description="Total number of pages")

class CreateTenantRequest(BaseModel):
    """Admin request to create new tenant"""
    name: str = Field(..., min_length=1, max_length=255, description="Full name")
    email: EmailStr = Field(..., description="Email address")
    company_name: Optional[str] = Field(None, max_length=255, description="Company name")
    role: str = Field(default="user", description="User role")
    password: Optional[str] = Field(None, min_length=8, max_length=100, description="Password (optional)")
    is_verified: bool = Field(default=False, description="Email verification status")
    status: str = Field(default="active", description="Account status")

class UpdateTenantRequest(BaseModel):
    """Admin request to update tenant"""
    name: Optional[str] = Field(None, min_length=1, max_length=255, description="Full name")
    company_name: Optional[str] = Field(None, max_length=255, description="Company name")
    role: Optional[str] = Field(None, description="User role")
    is_verified: Optional[bool] = Field(None, description="Email verification status")
    status: Optional[str] = Field(None, description="Account status")

class SystemStatsResponse(BaseModel):
    """Global system statistics"""
    total_tenants: int = Field(..., description="Total number of tenants")
    active_tenants: int = Field(..., description="Active tenants")
    tenants_with_api_keys: int = Field(..., description="Tenants with API keys")
    jwt_enabled_tenants: int = Field(..., description="Tenants with JWT authentication")
    
    # Request stats
    total_requests_all_time: int = Field(..., description="Total detection requests")
    requests_last_24h: int = Field(..., description="Requests in last 24 hours")
    requests_last_7_days: int = Field(..., description="Requests in last 7 days")
    requests_last_30_days: int = Field(..., description="Requests in last 30 days")
    
    # Threat stats
    total_threats_blocked: int = Field(..., description="Total threats blocked")
    threats_last_24h: int = Field(..., description="Threats blocked last 24h")
    global_block_rate: float = Field(..., description="Global threat block rate %")
    
    # Top tenants by usage
    top_tenants_by_requests: List[Dict[str, Any]] = Field(..., description="Top 10 tenants by request count")

@router.get("/system/stats", response_model=SystemStatsResponse)
async def get_system_stats(
    admin_user: Tenant = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Get global system statistics and metrics
    Admin only
    """
    try:
        # Basic tenant counts
        total_tenants_query = select(func.count(Tenant.id))
        active_tenants_query = select(func.count(Tenant.id)).where(Tenant.status == 'active')
        api_key_tenants_query = select(func.count(Tenant.id)).join(TenantAPIKey)
        jwt_tenants_query = select(func.count(Tenant.id)).where(Tenant.password_hash.is_not(None))
        
        total_tenants = await db.execute(total_tenants_query)
        active_tenants = await db.execute(active_tenants_query)
        api_key_tenants = await db.execute(api_key_tenants_query)
        jwt_tenants = await db.execute(jwt_tenants_query)
        
        # Get analytics service for request stats
        analytics_service = TenantAnalyticsService(db)
        global_stats = await analytics_service.get_global_stats()
        
        # Top tenants by usage (simplified - would need proper analytics tables)
        top_tenants_query = select(Tenant.id, Tenant.name, Tenant.email).limit(10)
        top_tenants_result = await db.execute(top_tenants_query)
        top_tenants = [
            {
                "tenant_id": str(row.id),
                "name": row.name,
                "email": row.email,
                "request_count": 0  # Would come from analytics
            }
            for row in top_tenants_result
        ]
        
        logger.info("System stats retrieved", admin_id=str(admin_user.id))
        
        return SystemStatsResponse(
            total_tenants=total_tenants.scalar(),
            active_tenants=active_tenants.scalar(),
            tenants_with_api_keys=api_key_tenants.scalar(),
            jwt_enabled_tenants=jwt_tenants.scalar(),
            total_requests_all_time=global_stats.get("total_requests", 0),
            requests_last_24h=global_stats.get("requests_24h", 0),
            requests_last_7_days=global_stats.get("requests_7d", 0),
            requests_last_30_days=global_stats.get("requests_30d", 0),
            total_threats_blocked=global_stats.get("threats_blocked", 0),
            threats_last_24h=global_stats.get("threats_24h", 0),
            global_block_rate=global_stats.get("block_rate", 0.0),
            top_tenants_by_requests=top_tenants
        )
        
    except Exception as e:
        logger.error("Failed to get system stats", admin_id=str(admin_user.id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve system statistics"
        )

@router.get("/tenants", response_model=TenantListResponse)
async def list_all_tenants(
    admin_user: Tenant = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(default=None, description="Search by name or email"),
    role_filter: Optional[str] = Query(default=None, description="Filter by role"),
    status_filter: Optional[str] = Query(default=None, description="Filter by status")
):
    """
    List all tenants with pagination and filtering
    Admin only
    """
    try:
        # Build base query
        query = select(Tenant).outerjoin(TenantAPIKey)
        count_query = select(func.count(Tenant.id))
        
        # Apply filters
        conditions = []
        
        if search:
            search_term = f"%{search.lower()}%"
            conditions.append(
                or_(
                    Tenant.name.ilike(search_term),
                    Tenant.email.ilike(search_term),
                    Tenant.company_name.ilike(search_term)
                )
            )
        
        if role_filter:
            conditions.append(Tenant.role == role_filter)
        
        if status_filter:
            conditions.append(Tenant.status == status_filter)
        
        if conditions:
            query = query.where(and_(*conditions))
            count_query = count_query.where(and_(*conditions))
        
        # Get total count
        total_result = await db.execute(count_query)
        total_count = total_result.scalar()
        
        # Apply pagination and ordering
        offset = (page - 1) * page_size
        query = query.order_by(desc(Tenant.created_at)).offset(offset).limit(page_size)
        
        result = await db.execute(query)
        tenants = result.scalars().all()
        
        # Convert to response format
        tenant_summaries = []
        analytics_service = TenantAnalyticsService(db)
        
        for tenant in tenants:
            # Get usage stats for each tenant
            usage_stats = await analytics_service.get_tenant_summary(str(tenant.id))
            
            tenant_summaries.append(TenantSummary(
                id=str(tenant.id),
                name=tenant.name,
                email=tenant.email,
                company_name=tenant.company_name,
                role=tenant.role,
                status=tenant.status,
                is_verified=tenant.is_email_verified,
                is_authenticated=tenant.is_authenticated,
                created_at=tenant.created_at.isoformat(),
                last_login=tenant.last_login.isoformat() if tenant.last_login else None,
                has_api_key=tenant.api_key is not None,
                api_key_created_at=tenant.api_key.created_at.isoformat() if tenant.api_key else None,
                api_key_last_used=tenant.api_key.last_used_at.isoformat() if tenant.api_key and tenant.api_key.last_used_at else None,
                total_requests=usage_stats.get("total_requests", 0),
                requests_last_30_days=usage_stats.get("requests_30d", 0),
                threats_blocked=usage_stats.get("threats_blocked", 0)
            ))
        
        total_pages = (total_count + page_size - 1) // page_size
        
        logger.info("Tenants listed", 
                   admin_id=str(admin_user.id),
                   total_count=total_count,
                   page=page,
                   filters={"search": search, "role": role_filter, "status": status_filter})
        
        return TenantListResponse(
            tenants=tenant_summaries,
            total_count=total_count,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )
        
    except Exception as e:
        logger.error("Failed to list tenants", admin_id=str(admin_user.id), error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve tenants"
        )

@router.get("/tenants/{tenant_id}", response_model=TenantSummary)
async def get_tenant_details(
    tenant_id: UUID,
    admin_user: Tenant = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed information about a specific tenant
    Admin only
    """
    try:
        # Get tenant with API key
        query = select(Tenant).outerjoin(TenantAPIKey).where(Tenant.id == tenant_id)
        result = await db.execute(query)
        tenant = result.scalar_one_or_none()
        
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tenant not found"
            )
        
        # Get usage statistics
        analytics_service = TenantAnalyticsService(db)
        usage_stats = await analytics_service.get_tenant_summary(str(tenant.id))
        
        logger.info("Tenant details retrieved", 
                   admin_id=str(admin_user.id),
                   target_tenant_id=str(tenant.id))
        
        return TenantSummary(
            id=str(tenant.id),
            name=tenant.name,
            email=tenant.email,
            company_name=tenant.company_name,
            role=tenant.role,
            status=tenant.status,
            is_verified=tenant.is_email_verified,
            is_authenticated=tenant.is_authenticated,
            created_at=tenant.created_at.isoformat(),
            last_login=tenant.last_login.isoformat() if tenant.last_login else None,
            has_api_key=tenant.api_key is not None,
            api_key_created_at=tenant.api_key.created_at.isoformat() if tenant.api_key else None,
            api_key_last_used=tenant.api_key.last_used_at.isoformat() if tenant.api_key and tenant.api_key.last_used_at else None,
            total_requests=usage_stats.get("total_requests", 0),
            requests_last_30_days=usage_stats.get("requests_30d", 0),
            threats_blocked=usage_stats.get("threats_blocked", 0)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get tenant details", 
                    admin_id=str(admin_user.id),
                    tenant_id=str(tenant_id),
                    error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve tenant details"
        )

@router.post("/tenants", response_model=TenantSummary, status_code=status.HTTP_201_CREATED)
async def create_tenant(
    request: CreateTenantRequest,
    admin_user: Tenant = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Create new tenant (admin only)
    """
    try:
        # Check if email already exists
        existing_query = select(Tenant).where(Tenant.email == request.email.lower())
        existing_result = await db.execute(existing_query)
        existing_tenant = existing_result.scalar_one_or_none()
        
        if existing_tenant:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered"
            )
        
        # Create tenant
        tenant_data = {
            "name": request.name.strip(),
            "email": request.email.lower(),
            "company_name": request.company_name.strip() if request.company_name else None,
            "role": request.role,
            "status": request.status,
            "is_email_verified": request.is_verified
        }
        
        # Add password hash if password provided
        if request.password:
            from app.core.jwt_auth import hash_password
            tenant_data["password_hash"] = hash_password(request.password)
        
        tenant = Tenant(**tenant_data)
        
        db.add(tenant)
        await db.commit()
        await db.refresh(tenant)
        
        logger.info("Tenant created by admin", 
                   admin_id=str(admin_user.id),
                   new_tenant_id=str(tenant.id),
                   email=tenant.email)
        
        return TenantSummary(
            id=str(tenant.id),
            name=tenant.name,
            email=tenant.email,
            company_name=tenant.company_name,
            role=tenant.role,
            status=tenant.status,
            is_verified=tenant.is_email_verified,
            is_authenticated=tenant.is_authenticated,
            created_at=tenant.created_at.isoformat(),
            last_login=None,
            has_api_key=False,
            api_key_created_at=None,
            api_key_last_used=None,
            total_requests=0,
            requests_last_30_days=0,
            threats_blocked=0
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create tenant", 
                    admin_id=str(admin_user.id),
                    email=request.email,
                    error=str(e))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create tenant"
        )

@router.put("/tenants/{tenant_id}", response_model=TenantSummary)
async def update_tenant(
    tenant_id: UUID,
    request: UpdateTenantRequest,
    admin_user: Tenant = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Update tenant information (admin only)
    """
    try:
        # Get tenant
        query = select(Tenant).where(Tenant.id == tenant_id)
        result = await db.execute(query)
        tenant = result.scalar_one_or_none()
        
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tenant not found"
            )
        
        # Update fields
        updated_fields = []
        if request.name is not None:
            tenant.name = request.name.strip()
            updated_fields.append("name")
        
        if request.company_name is not None:
            tenant.company_name = request.company_name.strip() if request.company_name else None
            updated_fields.append("company_name")
        
        if request.role is not None:
            tenant.role = request.role
            updated_fields.append("role")
        
        if request.is_verified is not None:
            tenant.is_email_verified = request.is_verified
            updated_fields.append("is_verified")
        
        if request.status is not None:
            tenant.status = request.status
            updated_fields.append("status")
        
        if not updated_fields:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid fields to update"
            )
        
        tenant.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(tenant)
        
        # Get usage stats
        analytics_service = TenantAnalyticsService(db)
        usage_stats = await analytics_service.get_tenant_summary(str(tenant.id))
        
        logger.info("Tenant updated by admin", 
                   admin_id=str(admin_user.id),
                   tenant_id=str(tenant.id),
                   updated_fields=updated_fields)
        
        return TenantSummary(
            id=str(tenant.id),
            name=tenant.name,
            email=tenant.email,
            company_name=tenant.company_name,
            role=tenant.role,
            status=tenant.status,
            is_verified=tenant.is_email_verified,
            is_authenticated=tenant.is_authenticated,
            created_at=tenant.created_at.isoformat(),
            last_login=tenant.last_login.isoformat() if tenant.last_login else None,
            has_api_key=tenant.api_key is not None,
            api_key_created_at=tenant.api_key.created_at.isoformat() if tenant.api_key else None,
            api_key_last_used=tenant.api_key.last_used_at.isoformat() if tenant.api_key and tenant.api_key.last_used_at else None,
            total_requests=usage_stats.get("total_requests", 0),
            requests_last_30_days=usage_stats.get("requests_30d", 0),
            threats_blocked=usage_stats.get("threats_blocked", 0)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to update tenant", 
                    admin_id=str(admin_user.id),
                    tenant_id=str(tenant_id),
                    error=str(e))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update tenant"
        )

@router.delete("/tenants/{tenant_id}")
async def delete_tenant(
    tenant_id: UUID,
    admin_user: Tenant = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete tenant and all associated data (admin only)
    WARNING: This is a destructive operation
    """
    try:
        # Prevent admin from deleting themselves
        if str(admin_user.id) == str(tenant_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete your own admin account"
            )
        
        # Get tenant
        query = select(Tenant).where(Tenant.id == tenant_id)
        result = await db.execute(query)
        tenant = result.scalar_one_or_none()
        
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tenant not found"
            )
        
        # Delete associated API key first (if exists)
        if tenant.api_key:
            await db.delete(tenant.api_key)
        
        # Delete tenant
        tenant_email = tenant.email  # Store for logging
        await db.delete(tenant)
        await db.commit()
        
        logger.warning("Tenant deleted by admin", 
                      admin_id=str(admin_user.id),
                      deleted_tenant_id=str(tenant_id),
                      deleted_email=tenant_email)
        
        return {
            "success": True,
            "message": f"Tenant {tenant_email} deleted successfully",
            "tenant_id": str(tenant_id)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete tenant", 
                    admin_id=str(admin_user.id),
                    tenant_id=str(tenant_id),
                    error=str(e))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete tenant"
        )

@router.post("/tenants/{tenant_id}/revoke-api-key")
async def admin_revoke_api_key(
    tenant_id: UUID,
    admin_user: Tenant = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Revoke API key for any tenant (admin only)
    """
    try:
        # Get tenant with API key
        query = select(Tenant).outerjoin(TenantAPIKey).where(Tenant.id == tenant_id)
        result = await db.execute(query)
        tenant = result.scalar_one_or_none()
        
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tenant not found"
            )
        
        if not tenant.api_key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tenant has no API key to revoke"
            )
        
        # Delete API key
        api_key_id = str(tenant.api_key.id)
        await db.delete(tenant.api_key)
        await db.commit()
        
        logger.warning("API key revoked by admin", 
                      admin_id=str(admin_user.id),
                      tenant_id=str(tenant_id),
                      api_key_id=api_key_id)
        
        return {
            "success": True,
            "message": "API key revoked successfully",
            "tenant_id": str(tenant_id),
            "api_key_id": api_key_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to revoke API key", 
                    admin_id=str(admin_user.id),
                    tenant_id=str(tenant_id),
                    error=str(e))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke API key"
        )

@router.post("/tenants/{tenant_id}/generate-api-key")
async def admin_generate_api_key(
    tenant_id: UUID,
    admin_user: Tenant = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Generate API key for any tenant (admin only)
    """
    try:
        # Get tenant
        query = select(Tenant).outerjoin(TenantAPIKey).where(Tenant.id == tenant_id)
        result = await db.execute(query)
        tenant = result.scalar_one_or_none()
        
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tenant not found"
            )
        
        if tenant.api_key:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Tenant already has an API key. Revoke first."
            )
        
        # Generate API key
        api_key = tenant_auth.generate_api_key()
        key_hash = tenant_auth.hash_api_key(api_key)
        key_prefix = tenant_auth.get_key_prefix(api_key)
        
        # Create API key record
        api_key_record = TenantAPIKey(
            tenant_id=tenant.id,
            key_prefix=key_prefix,
            key_hash=key_hash,
            name=f"Admin Generated Key for {tenant.name}",
            is_active=True
        )
        
        db.add(api_key_record)
        await db.commit()
        await db.refresh(api_key_record)
        
        logger.warning("API key generated by admin", 
                      admin_id=str(admin_user.id),
                      tenant_id=str(tenant_id),
                      key_prefix=key_prefix)
        
        return {
            "success": True,
            "message": "API key generated successfully",
            "api_key": api_key,  # Only shown once
            "key_prefix": key_prefix,
            "tenant_id": str(tenant_id),
            "warning": "Store this API key securely. It cannot be retrieved again."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to generate API key", 
                    admin_id=str(admin_user.id),
                    tenant_id=str(tenant_id),
                    error=str(e))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate API key"
        )