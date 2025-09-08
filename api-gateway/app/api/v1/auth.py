"""
Authentication Endpoints
JWT-based login, registration, and token management
"""

import logging
from datetime import datetime
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr, Field

from app.core.database import get_db
from app.core.jwt_auth import (
    jwt_manager, 
    hash_password, 
    verify_password,
    TokenExpiredError,
    InvalidTokenError
)
from app.core.rbac import get_current_tenant_from_jwt, require_authentication
from app.models.tenant import Tenant

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)
security = HTTPBearer()

# Request/Response Models
class RegisterRequest(BaseModel):
    """User registration request"""
    name: str = Field(..., min_length=1, max_length=255, description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., min_length=8, max_length=100, description="Password (min 8 characters)")
    company_name: Optional[str] = Field(None, max_length=255, description="Company name")
    
    class Config:
        json_schema_extra = {
            "example": {
                "name": "John Doe",
                "email": "john@company.com", 
                "password": "SecurePass123!",
                "company_name": "Acme Corp"
            }
        }

class LoginRequest(BaseModel):
    """User login request"""
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., description="Password")
    
    class Config:
        json_schema_extra = {
            "example": {
                "email": "john@company.com",
                "password": "SecurePass123!"
            }
        }

class RefreshRequest(BaseModel):
    """Token refresh request"""
    refresh_token: str = Field(..., description="Valid refresh token")

class AuthResponse(BaseModel):
    """Authentication response with tokens"""
    success: bool = Field(default=True)
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer")
    expires_in: int = Field(..., description="Access token expiry in seconds")
    
    # User information
    tenant_id: str = Field(..., description="Tenant/User ID")
    email: str = Field(..., description="User email")
    name: str = Field(..., description="User name")
    role: str = Field(..., description="User role")
    company: Optional[str] = Field(None, description="Company name")
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...", 
                "token_type": "bearer",
                "expires_in": 1800,
                "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "john@company.com",
                "name": "John Doe",
                "role": "user",
                "company": "Acme Corp"
            }
        }

class TokenResponse(BaseModel):
    """Token refresh response"""
    access_token: str = Field(..., description="New JWT access token")
    token_type: str = Field(default="bearer")
    expires_in: int = Field(..., description="Access token expiry in seconds")

class MessageResponse(BaseModel):
    """Generic message response"""
    success: bool = Field(default=True)
    message: str = Field(..., description="Response message")

@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Register new user with JWT authentication
    Creates tenant account with password for platform access
    """
    try:
        # Check if email already exists
        query = select(Tenant).where(Tenant.email == request.email.lower())
        result = await db.execute(query)
        existing_tenant = result.scalar_one_or_none()
        
        if existing_tenant:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered"
            )
        
        # Hash password
        password_hash = hash_password(request.password)
        
        # Create new tenant with authentication
        tenant = Tenant(
            name=request.name.strip(),
            email=request.email.lower(),
            company_name=request.company_name.strip() if request.company_name else None,
            password_hash=password_hash,
            role='user',  # Default role
            status='active',
            is_email_verified=False  # Would be verified via email in production
        )
        
        db.add(tenant)
        await db.commit()
        await db.refresh(tenant)
        
        # Generate JWT token pair
        tokens = jwt_manager.create_token_pair(tenant)
        
        # Update last login
        tenant.update_last_login()
        await db.commit()
        
        logger.info("User registered successfully", 
                   tenant_id=str(tenant.id),
                   email=tenant.email,
                   role=tenant.role)
        
        return AuthResponse(
            access_token=tokens['access_token'],
            refresh_token=tokens['refresh_token'],
            expires_in=tokens['expires_in'],
            tenant_id=str(tenant.id),
            email=tenant.email,
            name=tenant.name,
            role=tenant.role,
            company=tenant.company_name
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Registration failed", email=request.email, error=str(e))
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed. Please try again."
        )

@router.post("/login", response_model=AuthResponse)
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and return JWT tokens
    """
    try:
        # Find tenant by email
        query = select(Tenant).where(Tenant.email == request.email.lower())
        result = await db.execute(query)
        tenant = result.scalar_one_or_none()
        
        if not tenant:
            # Don't reveal that email doesn't exist
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Check if tenant has password set (is JWT-authenticated)
        if not tenant.password_hash:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account not set up for login. Please use API key registration first."
            )
        
        # Verify password
        if not verify_password(request.password, tenant.password_hash):
            logger.warning("Failed login attempt", email=request.email)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Check if account is active
        if not tenant.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is inactive. Please contact support."
            )
        
        # Generate JWT token pair
        tokens = jwt_manager.create_token_pair(tenant)
        
        # Update last login
        tenant.update_last_login()
        await db.commit()
        
        logger.info("User logged in successfully", 
                   tenant_id=str(tenant.id),
                   email=tenant.email,
                   role=tenant.role)
        
        return AuthResponse(
            access_token=tokens['access_token'],
            refresh_token=tokens['refresh_token'],
            expires_in=tokens['expires_in'],
            tenant_id=str(tenant.id),
            email=tenant.email,
            name=tenant.name,
            role=tenant.role,
            company=tenant.company_name
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Login failed", email=request.email, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Login failed. Please try again."
        )

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: RefreshRequest
):
    """
    Refresh access token using valid refresh token
    """
    try:
        # Generate new access token
        new_access_token = jwt_manager.refresh_access_token(request.refresh_token)
        
        return TokenResponse(
            access_token=new_access_token,
            expires_in=jwt_manager.access_token_expire_minutes * 60
        )
        
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired. Please login again."
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    except Exception as e:
        logger.error("Token refresh failed", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )

@router.post("/logout", response_model=MessageResponse)
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Logout user by revoking their access token
    """
    try:
        if credentials:
            # Revoke the access token
            jwt_manager.revoke_token(credentials.credentials)
        
        logger.info("User logged out")
        
        return MessageResponse(
            message="Logged out successfully"
        )
        
    except Exception as e:
        logger.error("Logout failed", error=str(e))
        # Don't fail logout even if token revocation fails
        return MessageResponse(
            message="Logged out (with warnings)"
        )

@router.get("/me", response_model=Dict[str, Any])
async def get_current_user(
    tenant: Tenant = Depends(require_authentication)
):
    """
    Get current user information from JWT token
    """
    return {
        "tenant_id": str(tenant.id),
        "email": tenant.email,
        "name": tenant.name,
        "role": tenant.role,
        "company": tenant.company_name,
        "status": tenant.status,
        "is_verified": tenant.is_email_verified,
        "created_at": tenant.created_at.isoformat(),
        "last_login": tenant.last_login.isoformat() if tenant.last_login else None,
        "settings": tenant.settings
    }

@router.post("/verify-token")
async def verify_token_endpoint(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Verify if JWT token is valid (for debugging/monitoring)
    """
    try:
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No token provided"
            )
        
        # Get token info
        token_info = jwt_manager.get_token_info(credentials.credentials)
        
        # Also validate the token
        payload = jwt_manager.validate_token(credentials.credentials)
        
        return {
            "valid": True,
            "token_info": token_info,
            "payload": {
                "tenant_id": payload.get('sub'),
                "email": payload.get('email'),
                "role": payload.get('role'),
                "expires_at": payload.get('exp')
            }
        }
        
    except TokenExpiredError:
        return {
            "valid": False,
            "error": "Token has expired",
            "token_info": jwt_manager.get_token_info(credentials.credentials)
        }
    except InvalidTokenError as e:
        return {
            "valid": False,
            "error": str(e),
            "token_info": jwt_manager.get_token_info(credentials.credentials) if credentials else None
        }
    except Exception as e:
        logger.error("Token verification failed", error=str(e))
        return {
            "valid": False,
            "error": "Token verification failed"
        }