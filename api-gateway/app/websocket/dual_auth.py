"""
WebSocket Dual Authentication System
JWT + API Key authentication for real-time dashboard connections
"""

import logging
from datetime import datetime
from typing import Optional, Tuple, Dict, Any

from app.core.jwt_auth import jwt_manager, InvalidTokenError, TokenExpiredError
from app.core.tenant_auth import tenant_auth
from app.core.database import get_db_session
from app.models.tenant import Tenant, TenantAPIKey
from app.websocket.metrics import websocket_auth_attempts, websocket_errors

logger = logging.getLogger(__name__)

class DualAuthResult:
    """Result of dual authentication attempt"""
    
    def __init__(self, success: bool, tenant: Optional[Tenant] = None, 
                 api_key_record: Optional[TenantAPIKey] = None, 
                 error: Optional[str] = None, auth_context: Optional[Dict[str, Any]] = None):
        self.success = success
        self.tenant = tenant
        self.api_key_record = api_key_record
        self.error = error
        self.auth_context = auth_context or {}
    
    @property
    def tenant_id(self) -> Optional[str]:
        return str(self.tenant.id) if self.tenant else None
    
    @property
    def is_admin(self) -> bool:
        return self.tenant.is_admin if self.tenant else False

class WebSocketDualAuth:
    """
    Dual authentication system for WebSocket connections
    Requires both JWT token (for user context) and API Key (for tenant/billing context)
    """
    
    @staticmethod
    async def authenticate(auth_data: Dict[str, Any]) -> DualAuthResult:
        """
        Authenticate WebSocket connection using dual auth (JWT + API Key)
        
        Expected auth_data format:
        {
            "jwt_token": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
            "api_key": "pid_abc12345..."
        }
        """
        try:
            # Extract authentication credentials
            jwt_token = auth_data.get('jwt_token', '').replace('Bearer ', '')
            api_key = auth_data.get('api_key', '')
            
            if not jwt_token or not api_key:
                missing = []
                if not jwt_token:
                    missing.append("JWT token")
                if not api_key:
                    missing.append("API key")
                
                error_msg = f"Missing authentication credentials: {', '.join(missing)}"
                logger.warning("WebSocket dual auth failed", error=error_msg)
                websocket_auth_attempts.labels(status='failed_missing_credentials').inc()
                
                return DualAuthResult(
                    success=False,
                    error=error_msg
                )
            
            # Step 1: Validate JWT token and get user context
            jwt_result = await WebSocketDualAuth._validate_jwt(jwt_token)
            if not jwt_result['success']:
                websocket_auth_attempts.labels(status='failed_invalid_jwt').inc()
                return DualAuthResult(
                    success=False,
                    error=jwt_result['error']
                )
            
            jwt_payload = jwt_result['payload']
            jwt_tenant_id = jwt_payload.get('sub')
            
            # Step 2: Validate API key and get tenant/billing context
            api_result = await WebSocketDualAuth._validate_api_key(api_key)
            if not api_result['success']:
                websocket_auth_attempts.labels(status='failed_invalid_api_key').inc()
                return DualAuthResult(
                    success=False,
                    error=api_result['error']
                )
            
            api_tenant = api_result['tenant']
            api_key_record = api_result['api_key_record']
            api_tenant_id = str(api_tenant.id)
            
            # Step 3: Verify JWT and API key belong to same tenant
            if jwt_tenant_id != api_tenant_id:
                error_msg = f"JWT tenant ({jwt_tenant_id}) doesn't match API key tenant ({api_tenant_id})"
                logger.warning("WebSocket dual auth failed", error=error_msg)
                websocket_auth_attempts.labels(status='failed_tenant_mismatch').inc()
                
                return DualAuthResult(
                    success=False,
                    error="Authentication credentials belong to different tenants"
                )
            
            # Step 4: Verify tenant is active and can use WebSocket
            if api_tenant.status != 'active':
                error_msg = f"Tenant {api_tenant_id} is not active (status: {api_tenant.status})"
                logger.warning("WebSocket dual auth failed", error=error_msg)
                websocket_auth_attempts.labels(status='failed_inactive_tenant').inc()
                
                return DualAuthResult(
                    success=False,
                    error="Account is not active"
                )
            
            if not api_key_record.is_active:
                error_msg = f"API key for tenant {api_tenant_id} is not active"
                logger.warning("WebSocket dual auth failed", error=error_msg)
                websocket_auth_attempts.labels(status='failed_inactive_api_key').inc()
                
                return DualAuthResult(
                    success=False,
                    error="API key is not active"
                )
            
            # Step 5: Update API key usage
            api_key_record.update_last_used()
            async with get_db_session() as db:
                db.add(api_key_record)
                await db.commit()
            
            # Step 6: Create authentication context
            auth_context = {
                'jwt_payload': jwt_payload,
                'api_key_prefix': api_key_record.key_prefix,
                'authenticated_at': datetime.utcnow().isoformat(),
                'auth_method': 'dual_jwt_api_key',
                'permissions': WebSocketDualAuth._get_websocket_permissions(api_tenant),
                'rate_limits': WebSocketDualAuth._get_rate_limits(api_tenant)
            }
            
            logger.info("WebSocket dual authentication successful", 
                       tenant_id=api_tenant_id,
                       tenant_name=api_tenant.name,
                       role=api_tenant.role,
                       api_key_prefix=api_key_record.key_prefix)
            
            websocket_auth_attempts.labels(status='success_dual_auth').inc()
            
            return DualAuthResult(
                success=True,
                tenant=api_tenant,
                api_key_record=api_key_record,
                auth_context=auth_context
            )
            
        except Exception as e:
            logger.error("WebSocket dual authentication error", error=str(e), exc_info=True)
            websocket_errors.labels(error_type=type(e).__name__).inc()
            
            return DualAuthResult(
                success=False,
                error="Authentication system error"
            )
    
    @staticmethod
    async def _validate_jwt(jwt_token: str) -> Dict[str, Any]:
        """Validate JWT token and return payload"""
        try:
            # Validate token
            payload = jwt_manager.validate_token(jwt_token, 'access')
            
            # Check if tenant still exists and is active
            tenant_id = payload.get('sub')
            if not tenant_id:
                return {'success': False, 'error': 'Invalid JWT payload: missing subject'}
            
            # Verify tenant exists and is active (JWT might be valid but tenant deactivated)
            async with get_db_session() as db:
                from sqlalchemy import select
                query = select(Tenant).where(Tenant.id == tenant_id)
                result = await db.execute(query)
                tenant = result.scalar_one_or_none()
                
                if not tenant:
                    return {'success': False, 'error': 'Tenant not found'}
                
                if not tenant.is_active:
                    return {'success': False, 'error': 'Tenant account is inactive'}
            
            return {
                'success': True,
                'payload': payload,
                'tenant_id': tenant_id
            }
            
        except TokenExpiredError:
            return {'success': False, 'error': 'JWT token has expired'}
        except InvalidTokenError as e:
            return {'success': False, 'error': f'Invalid JWT token: {str(e)}'}
        except Exception as e:
            logger.error("JWT validation error", error=str(e))
            return {'success': False, 'error': 'JWT validation failed'}
    
    @staticmethod
    async def _validate_api_key(api_key: str) -> Dict[str, Any]:
        """Validate API key and return tenant + api_key_record"""
        try:
            async with get_db_session() as db:
                result = await tenant_auth.get_tenant_from_api_key(db, api_key)
                
                if not result:
                    return {'success': False, 'error': 'Invalid API key'}
                
                tenant, api_key_record = result
                
                return {
                    'success': True,
                    'tenant': tenant,
                    'api_key_record': api_key_record
                }
                
        except Exception as e:
            logger.error("API key validation error", error=str(e))
            return {'success': False, 'error': 'API key validation failed'}
    
    @staticmethod
    def _get_websocket_permissions(tenant: Tenant) -> Dict[str, bool]:
        """Get WebSocket permissions based on tenant role and status"""
        base_permissions = {
            'receive_detections': True,
            'receive_metrics': True,
            'receive_alerts': True,
            'request_stats': True,
        }
        
        # Admin permissions
        if tenant.is_admin:
            admin_permissions = {
                'receive_global_metrics': True,
                'receive_system_alerts': True,
                'view_all_tenants': True,
                'manage_connections': True
            }
            base_permissions.update(admin_permissions)
        
        return base_permissions
    
    @staticmethod
    def _get_rate_limits(tenant: Tenant) -> Dict[str, int]:
        """Get WebSocket rate limits based on tenant settings"""
        # Get tenant-specific rate limits from settings
        base_limits = {
            'events_per_minute': 60,  # 1 event per second
            'stats_requests_per_minute': 10,
            'max_connection_duration_hours': 24
        }
        
        # Admin gets higher limits
        if tenant.is_admin:
            admin_limits = {
                'events_per_minute': 120,
                'stats_requests_per_minute': 30,
                'max_connection_duration_hours': 48
            }
            base_limits.update(admin_limits)
        
        # Check tenant-specific settings
        if hasattr(tenant, 'settings') and tenant.settings:
            tenant_limits = tenant.settings.get('websocket_limits', {})
            base_limits.update(tenant_limits)
        
        return base_limits

class WebSocketLegacyAuth:
    """
    Legacy authentication for backward compatibility
    Only requires API Key (existing behavior)
    """
    
    @staticmethod
    async def authenticate(auth_data: Dict[str, Any]) -> DualAuthResult:
        """
        Legacy authentication using only API Key
        Maintained for backward compatibility with existing integrations
        """
        try:
            api_key = auth_data.get('api_key', '')
            
            if not api_key:
                logger.warning("WebSocket legacy auth failed: No API key provided")
                websocket_auth_attempts.labels(status='failed_missing_api_key').inc()
                return DualAuthResult(
                    success=False,
                    error="API key required"
                )
            
            # Validate API key
            async with get_db_session() as db:
                result = await tenant_auth.get_tenant_from_api_key(db, api_key)
                if not result:
                    logger.warning("WebSocket legacy auth failed: Invalid API key")
                    websocket_auth_attempts.labels(status='failed_invalid_api_key').inc()
                    return DualAuthResult(
                        success=False,
                        error="Invalid API key"
                    )
                
                tenant, api_key_record = result
            
            # Check tenant status
            if tenant.status != 'active' or not api_key_record.is_active:
                logger.warning("WebSocket legacy auth failed", 
                             tenant_id=str(tenant.id), 
                             tenant_status=tenant.status,
                             api_key_active=api_key_record.is_active)
                websocket_auth_attempts.labels(status='failed_inactive_account').inc()
                return DualAuthResult(
                    success=False,
                    error="Account or API key is not active"
                )
            
            # Update API key usage
            api_key_record.update_last_used()
            async with get_db_session() as db:
                db.add(api_key_record)
                await db.commit()
            
            # Create legacy auth context (limited permissions)
            auth_context = {
                'api_key_prefix': api_key_record.key_prefix,
                'authenticated_at': datetime.utcnow().isoformat(),
                'auth_method': 'legacy_api_key_only',
                'permissions': {
                    'receive_detections': True,
                    'receive_metrics': True,
                    'request_stats': True,
                    'receive_alerts': False,  # Limited for legacy
                    'receive_global_metrics': False,
                    'view_all_tenants': False
                },
                'rate_limits': {
                    'events_per_minute': 30,  # Lower limits for legacy
                    'stats_requests_per_minute': 5,
                    'max_connection_duration_hours': 12
                }
            }
            
            logger.info("WebSocket legacy authentication successful", 
                       tenant_id=str(tenant.id),
                       tenant_name=tenant.name,
                       api_key_prefix=api_key_record.key_prefix)
            
            websocket_auth_attempts.labels(status='success_legacy_auth').inc()
            
            return DualAuthResult(
                success=True,
                tenant=tenant,
                api_key_record=api_key_record,
                auth_context=auth_context
            )
            
        except Exception as e:
            logger.error("WebSocket legacy authentication error", error=str(e), exc_info=True)
            websocket_errors.labels(error_type=type(e).__name__).inc()
            
            return DualAuthResult(
                success=False,
                error="Authentication system error"
            )

# Factory function to choose authentication method
async def authenticate_websocket(auth_data: Dict[str, Any], prefer_dual_auth: bool = True) -> DualAuthResult:
    """
    Authenticate WebSocket connection using the appropriate method
    
    Args:
        auth_data: Authentication data from client
        prefer_dual_auth: Whether to prefer dual auth when both JWT and API key are provided
    
    Returns:
        DualAuthResult with authentication outcome
    """
    has_jwt = bool(auth_data.get('jwt_token', '').strip())
    has_api_key = bool(auth_data.get('api_key', '').strip())
    
    if has_jwt and has_api_key and prefer_dual_auth:
        # Use dual authentication (recommended for dashboard)
        logger.debug("Using dual authentication (JWT + API Key)")
        return await WebSocketDualAuth.authenticate(auth_data)
    
    elif has_api_key:
        # Use legacy authentication (API key only)
        logger.debug("Using legacy authentication (API Key only)")
        return await WebSocketLegacyAuth.authenticate(auth_data)
    
    else:
        # No valid authentication provided
        error_msg = "No valid authentication provided. Provide either API key only (legacy) or JWT + API key (recommended)"
        logger.warning("WebSocket authentication failed", error=error_msg)
        websocket_auth_attempts.labels(status='failed_no_valid_auth').inc()
        
        return DualAuthResult(
            success=False,
            error=error_msg
        )