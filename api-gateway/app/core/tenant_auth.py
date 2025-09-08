"""
Tenant Authentication - Clean implementation
No legacy support needed since not in production
"""

import bcrypt
import secrets
import hashlib
from typing import Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.models.tenant import Tenant, TenantAPIKey
from app.core.database import get_db


class TenantAuthenticator:
    """Clean tenant authentication without legacy support"""
    
    def __init__(self):
        self.security = HTTPBearer(auto_error=False)
    
    async def get_tenant_from_api_key(self, db: AsyncSession, api_key: str) -> Optional[Tuple[Tenant, TenantAPIKey]]:
        """
        Get tenant and API key info from API key string
        Returns None if invalid key or inactive tenant
        """
        if not api_key or not api_key.startswith('pid_'):
            return None
        
        # Extract prefix for faster lookup
        key_prefix = api_key[:12]  # pid_12345678
        
        # Query with joins for efficiency  
        query = select(TenantAPIKey, Tenant).join(
            Tenant, TenantAPIKey.tenant_id == Tenant.id
        ).where(
            and_(
                TenantAPIKey.key_prefix == key_prefix,
                TenantAPIKey.is_active == True,
                Tenant.status == 'active'
            )
        )
        result = await db.execute(query)
        row = result.first()
        
        if not row:
            return None
        
        api_key_record, tenant = row
        
        # Verify the full API key hash
        if not self._verify_api_key(api_key, api_key_record.key_hash):
            return None
        
        # Update last used timestamp (async in background)
        api_key_record.update_last_used()
        db.commit()
        
        return tenant, api_key_record
    
    def _verify_api_key(self, plain_key: str, hashed_key: str) -> bool:
        """Verify API key against hash"""
        try:
            return bcrypt.checkpw(plain_key.encode('utf-8'), hashed_key.encode('utf-8'))
        except Exception:
            return False
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate new API key in format: pid_12345678_random_secure_string"""
        prefix = secrets.token_hex(4)  # 8 hex chars
        suffix = secrets.token_urlsafe(32)  # 32 secure random chars
        return f"pid_{prefix}_{suffix}"
    
    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """Hash API key for storage"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(api_key.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def get_key_prefix(api_key: str) -> str:
        """Extract key prefix for database lookup"""
        if not api_key.startswith('pid_'):
            raise ValueError("Invalid API key format")
        return api_key[:12]  # pid_12345678


# Global authenticator instance
tenant_auth = TenantAuthenticator()


# Dependency functions for FastAPI
async def get_current_tenant(
    request: Request,
    db: AsyncSession = Depends(get_db)
) -> Tenant:
    """
    FastAPI dependency to get current tenant from API key
    Raises HTTPException if no valid tenant found
    """
    # Get API key from header
    api_key = request.headers.get("X-API-Key")
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required in X-API-Key header"
        )
    
    # Authenticate tenant
    result = await tenant_auth.get_tenant_from_api_key(db, api_key)
    
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key"
        )
    
    tenant, api_key_record = result
    
    # Store in request state for use in other parts of the app
    request.state.tenant = tenant
    request.state.api_key_record = api_key_record
    
    return tenant


async def get_tenant_context(request: Request) -> Optional[dict]:
    """
    Get tenant context if available (non-raising version)
    Returns None if no valid tenant, dict with tenant info if valid
    """
    if hasattr(request.state, 'tenant'):
        return {
            'tenant': request.state.tenant,
            'api_key_record': request.state.api_key_record
        }
    return None


# Rate limiting per tenant
class TenantRateLimiter:
    """Simple in-memory rate limiter per tenant"""
    
    def __init__(self):
        self._tenant_requests = {}  # In production, use Redis
    
    async def check_rate_limit(self, tenant: Tenant) -> bool:
        """
        Check if tenant has exceeded rate limit
        Returns True if allowed, False if rate limited
        """
        from datetime import datetime, timedelta
        
        tenant_id = str(tenant.id)
        rate_limit = tenant.rate_limit_per_minute
        now = datetime.utcnow()
        
        # Clean old entries
        if tenant_id in self._tenant_requests:
            cutoff = now - timedelta(minutes=1)
            self._tenant_requests[tenant_id] = [
                req_time for req_time in self._tenant_requests[tenant_id] 
                if req_time > cutoff
            ]
        else:
            self._tenant_requests[tenant_id] = []
        
        # Check current count
        current_count = len(self._tenant_requests[tenant_id])
        
        if current_count >= rate_limit:
            return False
        
        # Add current request
        self._tenant_requests[tenant_id].append(now)
        return True


# Global rate limiter instance
tenant_rate_limiter = TenantRateLimiter()


async def check_tenant_rate_limit(
    tenant: Tenant = Depends(get_current_tenant)
) -> Tenant:
    """
    FastAPI dependency to check tenant rate limiting
    Raises HTTPException if rate limited
    """
    if not await tenant_rate_limiter.check_rate_limit(tenant):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Maximum {tenant.rate_limit_per_minute} requests per minute."
        )
    
    return tenant