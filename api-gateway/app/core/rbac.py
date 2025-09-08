"""
Role-Based Access Control (RBAC) System
Provides decorators and dependencies for JWT-based authorization
"""

import logging
from typing import List, Optional, Dict, Any, Union
from functools import wraps

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt_auth import validate_token, InvalidTokenError, TokenExpiredError
from app.core.database import get_db
from app.models.tenant import Tenant
from sqlalchemy import select

logger = logging.getLogger(__name__)

# HTTP Bearer token scheme
security = HTTPBearer(auto_error=False)

class RBACError(Exception):
    """RBAC-related exceptions"""
    pass

class InsufficientPermissionsError(RBACError):
    """User doesn't have required permissions"""
    pass

class AuthenticationRequiredError(RBACError):
    """Authentication is required but not provided"""
    pass

async def get_current_tenant_from_jwt(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> Optional[Tenant]:
    """
    FastAPI dependency to get current tenant from JWT token
    Returns None if no valid token, raises exception for invalid tokens
    """
    if not credentials:
        return None
    
    try:
        # Validate JWT token
        payload = validate_token(credentials.credentials, 'access')
        tenant_id = payload.get('sub')
        
        if not tenant_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload"
            )
        
        # Fetch tenant from database to ensure it's still active
        query = select(Tenant).where(Tenant.id == tenant_id)
        result = await db.execute(query)
        tenant = result.scalar_one_or_none()
        
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Tenant not found"
            )
        
        if not tenant.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Tenant account is inactive"
            )
        
        # Update last login timestamp
        tenant.update_last_login()
        await db.commit()
        
        logger.debug("Tenant authenticated via JWT", 
                    tenant_id=str(tenant.id), 
                    role=tenant.role)
        
        return tenant
        
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("JWT authentication error", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed"
        )

async def require_authentication(
    tenant: Optional[Tenant] = Depends(get_current_tenant_from_jwt)
) -> Tenant:
    """
    FastAPI dependency that requires JWT authentication
    Raises 401 if no valid tenant found
    """
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    return tenant

async def require_role(required_roles: Union[str, List[str]]) -> Tenant:
    """
    Factory function to create role-based dependencies
    Usage: Depends(require_role('admin')) or Depends(require_role(['admin', 'user']))
    """
    if isinstance(required_roles, str):
        required_roles = [required_roles]
    
    async def role_checker(tenant: Tenant = Depends(require_authentication)) -> Tenant:
        if tenant.role not in required_roles:
            logger.warning("Access denied - insufficient role", 
                          tenant_id=str(tenant.id),
                          tenant_role=tenant.role,
                          required_roles=required_roles)
            
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role: {' or '.join(required_roles)}"
            )
        
        logger.debug("Role authorization successful",
                    tenant_id=str(tenant.id),
                    role=tenant.role)
        
        return tenant
    
    return role_checker

# Convenience dependencies for common roles
async def require_admin(tenant: Tenant = Depends(require_authentication)) -> Tenant:
    """Require admin role"""
    if not tenant.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return tenant

async def require_user(tenant: Tenant = Depends(require_authentication)) -> Tenant:
    """Require user role (any authenticated user)"""
    return tenant

def check_permissions(required_roles: Union[str, List[str]]):
    """
    Decorator for functions that need role-based access control
    Can be used on non-FastAPI functions
    """
    if isinstance(required_roles, str):
        required_roles = [required_roles]
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Look for tenant in kwargs (assumes it's passed from FastAPI dependency)
            tenant = kwargs.get('tenant') or kwargs.get('current_tenant')
            
            if not tenant:
                raise AuthenticationRequiredError("No authenticated tenant found")
            
            if tenant.role not in required_roles:
                raise InsufficientPermissionsError(
                    f"Role '{tenant.role}' insufficient. Required: {required_roles}"
                )
            
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator

class PermissionChecker:
    """
    Utility class for checking permissions in business logic
    """
    
    @staticmethod
    def can_access_admin_panel(tenant: Tenant) -> bool:
        """Check if tenant can access admin panel"""
        return tenant.is_admin and tenant.is_active
    
    @staticmethod
    def can_generate_api_key(tenant: Tenant) -> bool:
        """Check if tenant can generate API keys"""
        return tenant.is_active and tenant.is_authenticated
    
    @staticmethod
    def can_revoke_api_key(tenant: Tenant, target_tenant_id: str) -> bool:
        """Check if tenant can revoke API keys"""
        # Admin can revoke any key, user can only revoke their own
        return (tenant.is_admin or str(tenant.id) == target_tenant_id) and tenant.is_active
    
    @staticmethod
    def can_view_tenant_data(tenant: Tenant, target_tenant_id: str) -> bool:
        """Check if tenant can view other tenant's data"""
        # Admin can view any tenant, user can only view their own
        return tenant.is_admin or str(tenant.id) == target_tenant_id
    
    @staticmethod
    def can_manage_users(tenant: Tenant) -> bool:
        """Check if tenant can manage other users"""
        return tenant.is_admin and tenant.is_active
    
    @staticmethod
    def get_allowed_websocket_events(tenant: Tenant) -> List[str]:
        """Get list of WebSocket events tenant can access"""
        base_events = ['new_detection', 'metrics_update', 'connected', 'error']
        
        if tenant.is_admin:
            # Admin gets additional global events
            admin_events = ['global_metrics', 'system_status', 'all_tenant_activity']
            return base_events + admin_events
        
        return base_events

# Convenience functions for business logic
def check_admin_access(tenant: Tenant) -> None:
    """Raise exception if tenant doesn't have admin access"""
    if not PermissionChecker.can_access_admin_panel(tenant):
        raise InsufficientPermissionsError("Admin access required")

def check_api_key_generation(tenant: Tenant) -> None:
    """Raise exception if tenant can't generate API keys"""
    if not PermissionChecker.can_generate_api_key(tenant):
        raise InsufficientPermissionsError("Cannot generate API key - account inactive or not authenticated")

def check_tenant_access(requesting_tenant: Tenant, target_tenant_id: str) -> None:
    """Raise exception if tenant can't access target tenant data"""
    if not PermissionChecker.can_view_tenant_data(requesting_tenant, target_tenant_id):
        raise InsufficientPermissionsError("Access denied to tenant data")

# Global permission checker instance
permissions = PermissionChecker()