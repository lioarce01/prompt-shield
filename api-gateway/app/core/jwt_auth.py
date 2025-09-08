"""
JWT Authentication Core System
Handles token creation, validation, and refresh mechanisms
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Union
import secrets

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status

from app.core.config import get_settings
from app.models.tenant import Tenant

logger = logging.getLogger(__name__)

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class JWTError(Exception):
    """Custom JWT-related exceptions"""
    pass

class TokenExpiredError(JWTError):
    """Token has expired"""
    pass

class InvalidTokenError(JWTError):
    """Token is invalid or malformed"""
    pass

class JWTManager:
    """
    Central JWT token management system
    Handles creation, validation, and refresh of JWT tokens
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.secret_key = self.settings.SECRET_KEY
        self.algorithm = self.settings.security.jwt_algorithm
        self.access_token_expire_minutes = 30  # Short-lived access tokens
        self.refresh_token_expire_days = 7     # Long-lived refresh tokens
        
        # Token blacklist (in production, use Redis)
        self._blacklisted_tokens = set()
        
        logger.info("JWT Manager initialized", algorithm=self.algorithm)
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    def create_access_token(self, tenant: Tenant) -> str:
        """
        Create JWT access token for authenticated tenant
        Short-lived token for API access
        """
        if not tenant.is_authenticated:
            raise JWTError("Tenant must have password set to generate JWT")
        
        # Token payload with standard JWT claims
        payload = {
            # Standard JWT claims
            'sub': str(tenant.id),  # Subject (tenant ID)
            'iat': datetime.now(timezone.utc),  # Issued at
            'exp': datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes),
            'aud': 'prompt-shield-api',  # Audience
            'iss': 'prompt-shield-platform',  # Issuer
            'type': 'access',  # Token type
            
            # Custom claims
            'email': tenant.email,
            'name': tenant.name,
            'role': tenant.role,
            'company': tenant.company_name,
            'verified': tenant.is_email_verified,
            'active': tenant.is_active
        }
        
        try:
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            
            logger.info("Access token created", 
                       tenant_id=str(tenant.id),
                       role=tenant.role,
                       expires_in_minutes=self.access_token_expire_minutes)
            
            return token
            
        except Exception as e:
            logger.error("Failed to create access token", tenant_id=str(tenant.id), error=str(e))
            raise JWTError(f"Token creation failed: {str(e)}")
    
    def create_refresh_token(self, tenant: Tenant) -> str:
        """
        Create JWT refresh token for token renewal
        Long-lived token for refreshing access tokens
        """
        payload = {
            'sub': str(tenant.id),
            'iat': datetime.now(timezone.utc),
            'exp': datetime.now(timezone.utc) + timedelta(days=self.refresh_token_expire_days),
            'aud': 'prompt-shield-refresh',
            'iss': 'prompt-shield-platform',
            'type': 'refresh',
            'jti': secrets.token_hex(16)  # JWT ID for token tracking
        }
        
        try:
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            
            logger.info("Refresh token created", 
                       tenant_id=str(tenant.id),
                       expires_in_days=self.refresh_token_expire_days)
            
            return token
            
        except Exception as e:
            logger.error("Failed to create refresh token", tenant_id=str(tenant.id), error=str(e))
            raise JWTError(f"Refresh token creation failed: {str(e)}")
    
    def validate_token(self, token: str, token_type: str = 'access') -> Dict[str, Any]:
        """
        Validate and decode JWT token
        Returns payload if valid, raises exception if invalid
        """
        if token in self._blacklisted_tokens:
            raise InvalidTokenError("Token has been revoked")
        
        try:
            # Decode and validate token
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                audience=f'prompt-shield-{token_type}' if token_type == 'refresh' else 'prompt-shield-api'
            )
            
            # Validate token type
            if payload.get('type') != token_type:
                raise InvalidTokenError(f"Expected {token_type} token, got {payload.get('type')}")
            
            # Check if token is expired (jose should handle this, but double-check)
            exp_timestamp = payload.get('exp')
            if exp_timestamp and datetime.fromtimestamp(exp_timestamp, timezone.utc) < datetime.now(timezone.utc):
                raise TokenExpiredError("Token has expired")
            
            logger.debug("Token validated successfully", 
                        tenant_id=payload.get('sub'),
                        token_type=token_type)
            
            return payload
            
        except JWTError as e:
            if "expired" in str(e).lower():
                raise TokenExpiredError("Token has expired")
            else:
                raise InvalidTokenError(f"Invalid token: {str(e)}")
        except Exception as e:
            logger.warning("Token validation failed", token=token[:20] + "...", error=str(e))
            raise InvalidTokenError(f"Token validation error: {str(e)}")
    
    def refresh_access_token(self, refresh_token: str) -> str:
        """
        Create new access token using valid refresh token
        """
        try:
            # Validate refresh token
            payload = self.validate_token(refresh_token, 'refresh')
            tenant_id = payload.get('sub')
            
            if not tenant_id:
                raise InvalidTokenError("Invalid refresh token payload")
            
            # In a real implementation, you'd fetch the tenant from DB to ensure it's still active
            # For now, we'll create a minimal payload for the new access token
            new_payload = {
                'sub': tenant_id,
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(minutes=self.access_token_expire_minutes),
                'aud': 'prompt-shield-api',
                'iss': 'prompt-shield-platform',
                'type': 'access',
                # Note: In production, fetch fresh tenant data from DB
                'role': payload.get('role', 'user')  # Temporary - should be from DB
            }
            
            new_token = jwt.encode(new_payload, self.secret_key, algorithm=self.algorithm)
            
            logger.info("Access token refreshed", tenant_id=tenant_id)
            return new_token
            
        except (TokenExpiredError, InvalidTokenError):
            raise
        except Exception as e:
            logger.error("Token refresh failed", error=str(e))
            raise JWTError(f"Failed to refresh token: {str(e)}")
    
    def revoke_token(self, token: str) -> None:
        """
        Revoke token by adding to blacklist
        In production, store in Redis with TTL = token expiry
        """
        self._blacklisted_tokens.add(token)
        logger.info("Token revoked", token_prefix=token[:20] + "...")
    
    def get_token_info(self, token: str) -> Dict[str, Any]:
        """
        Get information about a token without full validation
        Useful for debugging and monitoring
        """
        try:
            # Decode without verification to get payload info
            payload = jwt.decode(token, options={"verify_signature": False})
            
            return {
                'tenant_id': payload.get('sub'),
                'email': payload.get('email'),
                'role': payload.get('role'),
                'type': payload.get('type'),
                'issued_at': payload.get('iat'),
                'expires_at': payload.get('exp'),
                'is_expired': payload.get('exp', 0) < datetime.now(timezone.utc).timestamp()
            }
        except Exception as e:
            logger.warning("Failed to get token info", error=str(e))
            return {'error': str(e)}
    
    def create_token_pair(self, tenant: Tenant) -> Dict[str, str]:
        """
        Create both access and refresh tokens for a tenant
        Convenience method for login flows
        """
        access_token = self.create_access_token(tenant)
        refresh_token = self.create_refresh_token(tenant)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer',
            'expires_in': self.access_token_expire_minutes * 60  # seconds
        }

# Global JWT manager instance
jwt_manager = JWTManager()

# Convenience functions for external use
def create_access_token(tenant: Tenant) -> str:
    """Create access token for tenant"""
    return jwt_manager.create_access_token(tenant)

def create_refresh_token(tenant: Tenant) -> str:
    """Create refresh token for tenant"""
    return jwt_manager.create_refresh_token(tenant)

def validate_token(token: str, token_type: str = 'access') -> Dict[str, Any]:
    """Validate JWT token"""
    return jwt_manager.validate_token(token, token_type)

def hash_password(password: str) -> str:
    """Hash password"""
    return jwt_manager.hash_password(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password"""
    return jwt_manager.verify_password(plain_password, hashed_password)