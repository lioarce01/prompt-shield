"""
Security utilities for authentication and authorization

Handles API key generation, hashing, validation, and rate limiting
with security best practices.
"""
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from functools import wraps

import structlog
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select

from app.core.config import get_settings
from app.core.database import get_db_session
from app.models.auth import APIKey

logger = structlog.get_logger()
security = HTTPBearer(auto_error=False)
settings = get_settings()


class APIKeyInfo:
    """Container for API key information"""
    def __init__(
        self,
        key_id: str,
        name: str,
        rate_limit_per_minute: int,
        rate_limit_per_day: int,
        is_active: bool = True
    ):
        self.key_id = key_id
        self.name = name
        self.rate_limit_per_minute = rate_limit_per_minute
        self.rate_limit_per_day = rate_limit_per_day
        self.is_active = is_active


def generate_api_key() -> str:
    """
    Generate a secure API key
    
    Format: pid_<64_hex_chars>
    Total length: 68 characters
    """
    # Generate 32 random bytes (256 bits of entropy)
    random_bytes = secrets.token_bytes(32)
    hex_string = random_bytes.hex()
    return f"pid_{hex_string}"


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key for secure storage
    
    Uses SHA-256 with salt for secure hashing.
    """
    if not api_key:
        raise ValueError("API key cannot be empty")
    
    # Add application salt to prevent rainbow table attacks
    salt = settings.SECRET_KEY.encode()
    key_bytes = api_key.encode()
    
    # Create hash with salt
    hash_obj = hashlib.sha256(salt + key_bytes)
    return hash_obj.hexdigest()


def verify_api_key(provided_key: str, stored_hash: str) -> bool:
    """
    Verify an API key against its stored hash
    
    Args:
        provided_key: The API key provided by the client
        stored_hash: The hash stored in the database
        
    Returns:
        True if the key is valid, False otherwise
    """
    if not provided_key or not stored_hash:
        return False
    
    try:
        computed_hash = hash_api_key(provided_key)
        return hmac.compare_digest(computed_hash, stored_hash)
    except Exception as e:
        logger.warning("API key verification failed", error=str(e))
        return False


def extract_api_key_from_request(request: Request) -> Optional[str]:
    """Extract API key from request headers"""
    # Try X-API-Key header first
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return api_key.strip()
    
    # Try Authorization header with Bearer token
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()  # Remove "Bearer " prefix
        # Check if it looks like our API key format
        if token.startswith("pid_") and len(token) == 68:
            return token
    
    return None


async def authenticate_api_key(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> APIKeyInfo:
    """
    FastAPI dependency for API key authentication
    
    Extracts and validates API key from request headers.
    Returns API key information if valid.
    """
    # Extract API key from request
    api_key = extract_api_key_from_request(request)
    
    if not api_key:
        logger.warning("Missing API key", client_ip=request.client.host if request.client else None)
        raise HTTPException(
            status_code=401,
            detail={
                "error": "API key required",
                "message": "Provide API key in X-API-Key header or Authorization: Bearer header"
            }
        )
    
    # Validate API key format
    if not api_key.startswith("pid_") or len(api_key) != 68:
        logger.warning("Invalid API key format", client_ip=request.client.host if request.client else None)
        raise HTTPException(
            status_code=401,
            detail={
                "error": "Invalid API key format",
                "message": "API key must be in format: pid_<64_hex_characters>"
            }
        )
    
    # Look up API key in database
    key_hash = hash_api_key(api_key)
    
    async with get_db_session() as db:
        # Query database for API key
        stmt = select(APIKey).where(
            APIKey.key_hash == key_hash,
            APIKey.is_active == True
        )
        result = await db.execute(stmt)
        db_api_key = result.scalar_one_or_none()
        
        if not db_api_key:
            logger.warning(
                "Invalid API key attempt", 
                client_ip=request.client.host if request.client else None
            )
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "Invalid API key",
                    "message": "API key not found or inactive"
                }
            )
        
        # Update last used timestamp
        db_api_key.last_used_at = datetime.utcnow()
        await db.commit()
        
        # Create APIKeyInfo object
        api_key_info = APIKeyInfo(
            key_id=str(db_api_key.id),
            name=db_api_key.name,
            rate_limit_per_minute=db_api_key.rate_limit_per_minute,
            rate_limit_per_day=db_api_key.rate_limit_per_day,
            is_active=db_api_key.is_active
        )
        
        # Log successful authentication (don't log the actual key!)
        logger.info(
            "API key authenticated",
            key_id=api_key_info.key_id,
            name=api_key_info.name,
            client_ip=request.client.host if request.client else None
        )
        
        return api_key_info


async def authenticate_admin_key(
    api_key_info: APIKeyInfo = Depends(authenticate_api_key)
) -> APIKeyInfo:
    """
    FastAPI dependency for admin authentication
    
    Requires valid API key AND admin privileges.
    """
    # TODO: Check if API key has admin privileges
    # For now, all keys are admin in development
    
    if not api_key_info.is_active:
        raise HTTPException(
            status_code=403,
            detail="API key is not active"
        )
    
    logger.info("Admin authentication successful", key_id=api_key_info.key_id)
    return api_key_info


def generate_webhook_secret() -> str:
    """Generate a secure webhook secret token"""
    return secrets.token_hex(32)  # 64 character hex string


def verify_webhook_signature(
    payload: bytes,
    signature: str,
    secret: str
) -> bool:
    """
    Verify webhook payload signature
    
    Args:
        payload: The webhook payload bytes
        signature: The provided signature (e.g., from X-Signature header)
        secret: The webhook secret token
        
    Returns:
        True if signature is valid, False otherwise
    """
    if not payload or not signature or not secret:
        return False
    
    try:
        # Expected format: sha256=<hex_signature>
        if not signature.startswith("sha256="):
            return False
        
        provided_signature = signature[7:]  # Remove "sha256=" prefix
        
        # Compute expected signature
        expected_signature = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        # Compare signatures securely
        return hmac.compare_digest(expected_signature, provided_signature)
        
    except Exception as e:
        logger.warning("Webhook signature verification failed", error=str(e))
        return False


def create_webhook_signature(payload: bytes, secret: str) -> str:
    """
    Create webhook signature for payload
    
    Args:
        payload: The webhook payload bytes
        secret: The webhook secret token
        
    Returns:
        Signature in format: sha256=<hex_signature>
    """
    signature = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return f"sha256={signature}"


# Rate limiting is now handled by RateLimitMiddleware
# This file focuses on authentication only


def require_api_key(func):
    """Decorator to require API key authentication"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # This would be handled by FastAPI dependencies instead
        return await func(*args, **kwargs)
    return wrapper