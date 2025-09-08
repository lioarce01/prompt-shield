"""
WebSocket authentication with dual auth support (JWT + API Key)
Backward compatible with legacy API key only authentication
"""

import logging
from datetime import datetime
from typing import Optional

from app.core.tenant_auth import tenant_auth
from app.models.tenant import Tenant
from app.websocket.manager import manager
from app.websocket.socketio_server import get_socketio_server
from app.websocket.metrics import websocket_auth_attempts, websocket_errors
from app.websocket.dual_auth import authenticate_websocket, DualAuthResult

logger = logging.getLogger(__name__)

async def setup_socketio_handlers():
    """Setup Socket.IO event handlers"""
    sio = await get_socketio_server()
    
    @sio.event
    async def connect(sid, environ, auth):
        """Handle client connection with dual authentication (JWT + API Key) or legacy API key only"""
        try:
            # Ensure auth is provided
            if not auth or not isinstance(auth, dict):
                logger.warning(f"WebSocket connection {sid} rejected: No authentication data provided")
                websocket_auth_attempts.labels(status='failed_no_auth_data').inc()
                return False
            
            # Attempt authentication using dual auth system
            auth_result: DualAuthResult = await authenticate_websocket(auth, prefer_dual_auth=True)
            
            if not auth_result.success:
                logger.warning(f"WebSocket connection {sid} rejected", error=auth_result.error)
                return False
            
            tenant = auth_result.tenant
            api_key_record = auth_result.api_key_record
            auth_context = auth_result.auth_context
            
            # Join tenant room with enhanced context
            await manager.join_tenant_room(sid, str(tenant.id), tenant.name, auth_context)
            
            # Prepare connection response with authentication details
            connection_data = {
                'tenant_id': str(tenant.id),
                'tenant_name': tenant.name,
                'company': tenant.company_name,
                'role': tenant.role,
                'connection_id': sid,
                'server_time': datetime.utcnow().isoformat(),
                'auth_method': auth_context.get('auth_method', 'unknown'),
                'permissions': auth_context.get('permissions', {}),
                'rate_limits': auth_context.get('rate_limits', {}),
                'message': f'Connected to Prompt Shield Dashboard as {tenant.name}'
            }
            
            # Add admin context for admin users
            if tenant.is_admin:
                connection_data['admin_context'] = {
                    'can_view_all_tenants': True,
                    'can_manage_connections': True,
                    'global_metrics_access': True
                }
            
            # Send welcome message with enhanced context
            await sio.emit('connected', connection_data, room=sid)
            
            # Send current tenant stats (with permission check)
            if auth_context.get('permissions', {}).get('receive_metrics', False):
                stats = await get_tenant_initial_stats(tenant.id, auth_result.is_admin)
                await sio.emit('initial_stats', stats, room=sid)
            
            # Send admin global stats if admin
            if tenant.is_admin and auth_context.get('permissions', {}).get('receive_global_metrics', False):
                try:
                    global_stats = await get_global_initial_stats()
                    await sio.emit('global_stats', global_stats, room=sid)
                except Exception as e:
                    logger.warning(f"Failed to send global stats to admin {sid}: {e}")
            
            logger.info(f"WebSocket client {sid} connected successfully", 
                       tenant_id=str(tenant.id), 
                       tenant_name=tenant.name,
                       company=tenant.company_name,
                       role=tenant.role,
                       auth_method=auth_context.get('auth_method'),
                       api_key_prefix=api_key_record.key_prefix if api_key_record else None)
            
            return True
            
        except Exception as e:
            logger.error(f"WebSocket connection error for {sid}: {e}", exc_info=True)
            websocket_errors.labels(error_type=type(e).__name__).inc()
            return False
    
    @sio.event
    async def disconnect(sid):
        """Handle client disconnection"""
        try:
            # Get tenant info before cleanup
            metadata = manager.get_session_metadata(sid)
            tenant_id = manager.session_tenants.get(sid)
            
            # Leave tenant room and cleanup
            await manager.leave_tenant_room(sid)
            
            if metadata:
                logger.info(f"WebSocket client {sid} disconnected", 
                           tenant_id=metadata.get('tenant_id'),
                           tenant_name=metadata.get('tenant_name'),
                           connected_duration=_calculate_duration(metadata.get('connected_at')))
            else:
                logger.info(f"WebSocket client {sid} disconnected (no metadata)")
                
        except Exception as e:
            logger.error(f"Error handling disconnect for {sid}: {e}")
            websocket_errors.labels(error_type=type(e).__name__).inc()
    
    @sio.event
    async def ping(sid):
        """Handle ping events for keepalive"""
        try:
            manager.update_session_activity(sid)
            await sio.emit('pong', {'timestamp': datetime.utcnow().isoformat()}, room=sid)
        except Exception as e:
            logger.error(f"Error handling ping from {sid}: {e}")
    
    @sio.event
    async def get_stats(sid, data=None):
        """Handle request for current stats"""
        try:
            tenant_id = manager.session_tenants.get(sid)
            if not tenant_id:
                return {'error': 'Not authenticated'}
            
            # Check rate limiting
            if not manager.rate_limiter.is_allowed(sid):
                await sio.emit('rate_limited', {
                    'message': 'Too many requests, please slow down'
                }, room=sid)
                return
            
            stats = await get_tenant_current_stats(tenant_id)
            await sio.emit('stats_update', stats, room=sid)
            
        except Exception as e:
            logger.error(f"Error handling get_stats from {sid}: {e}")
            await sio.emit('error', {'message': 'Failed to get stats'}, room=sid)
    
    @sio.event
    async def subscribe_events(sid, data):
        """Handle event subscription requests"""
        try:
            tenant_id = manager.session_tenants.get(sid)
            if not tenant_id:
                return {'error': 'Not authenticated'}
            
            # For now, all connected clients automatically get all events
            # In the future, we could implement selective event subscriptions
            await sio.emit('subscription_confirmed', {
                'subscribed_events': ['new_detection', 'metrics_update', 'system_status'],
                'message': 'Subscribed to all available events'
            }, room=sid)
            
        except Exception as e:
            logger.error(f"Error handling subscribe_events from {sid}: {e}")
    
    logger.info("Socket.IO event handlers registered")

async def get_tenant_initial_stats(tenant_id: str, is_admin: bool = False) -> dict:
    """Get initial statistics for a tenant"""
    try:
        # Get basic tenant stats - this would integrate with your existing analytics
        from app.services.tenant_analytics_service import TenantAnalyticsService
        from app.core.database import get_db_session
        
        async with get_db_session() as db:
            analytics_service = TenantAnalyticsService(db)
            stats = await analytics_service.get_tenant_summary(tenant_id)
        
        base_stats = {
            'tenant_id': tenant_id,
            'requests_today': stats.get('requests_today', 0),
            'threats_blocked_today': stats.get('threats_blocked_today', 0),
            'requests_last_hour': stats.get('requests_last_hour', 0),
            'average_response_time': stats.get('avg_response_time_ms', 0),
            'cache_hit_rate': stats.get('cache_hit_rate', 0.0),
            'top_threat_types': stats.get('top_threat_types', []),
            'status': 'active',
            'last_updated': datetime.utcnow().isoformat()
        }
        
        # Add admin-specific stats if user is admin
        if is_admin:
            admin_stats = {
                'admin_context': True,
                'total_requests_all_time': stats.get('total_requests', 0),
                'requests_last_7_days': stats.get('requests_7d', 0),
                'requests_last_30_days': stats.get('requests_30d', 0),
                'block_rate_percentage': stats.get('block_rate', 0.0),
                'tenant_analytics': {
                    'active_api_keys': 1 if stats.get('has_api_key') else 0,
                    'last_activity': stats.get('last_activity'),
                    'rate_limit_status': 'normal'  # This would come from rate limiter
                }
            }
            base_stats.update(admin_stats)
        
        return base_stats
        
    except Exception as e:
        logger.error(f"Failed to get initial stats for tenant {tenant_id}: {e}")
        return {
            'tenant_id': tenant_id,
            'requests_today': 0,
            'threats_blocked_today': 0,
            'requests_last_hour': 0,
            'average_response_time': 0,
            'cache_hit_rate': 0.0,
            'top_threat_types': [],
            'status': 'error',
            'error': 'Failed to load initial statistics',
            'last_updated': datetime.utcnow().isoformat()
        }

async def get_global_initial_stats() -> dict:
    """Get global system statistics for admin users"""
    try:
        from app.services.tenant_analytics_service import TenantAnalyticsService
        from app.core.database import get_db_session
        from sqlalchemy import select, func
        from app.models.tenant import Tenant, TenantAPIKey
        
        async with get_db_session() as db:
            # Get basic tenant counts
            total_tenants_query = select(func.count(Tenant.id))
            active_tenants_query = select(func.count(Tenant.id)).where(Tenant.status == 'active')
            admin_tenants_query = select(func.count(Tenant.id)).where(Tenant.role == 'admin')
            jwt_tenants_query = select(func.count(Tenant.id)).where(Tenant.password_hash.is_not(None))
            api_key_tenants_query = select(func.count(TenantAPIKey.id))
            
            total_tenants = (await db.execute(total_tenants_query)).scalar()
            active_tenants = (await db.execute(active_tenants_query)).scalar()
            admin_tenants = (await db.execute(admin_tenants_query)).scalar()
            jwt_tenants = (await db.execute(jwt_tenants_query)).scalar()
            api_key_count = (await db.execute(api_key_tenants_query)).scalar()
            
            # Get global analytics
            analytics_service = TenantAnalyticsService(db)
            global_stats = await analytics_service.get_global_stats()
            
            # Get WebSocket connection stats
            websocket_stats = manager.get_all_stats()
        
        return {
            'system_overview': {
                'total_tenants': total_tenants,
                'active_tenants': active_tenants,
                'admin_tenants': admin_tenants,
                'jwt_enabled_tenants': jwt_tenants,
                'total_api_keys': api_key_count
            },
            'request_metrics': {
                'total_requests_all_time': global_stats.get('total_requests', 0),
                'requests_last_24h': global_stats.get('requests_24h', 0),
                'requests_last_7_days': global_stats.get('requests_7d', 0),
                'threats_blocked_total': global_stats.get('threats_blocked', 0),
                'global_block_rate': global_stats.get('block_rate', 0.0)
            },
            'websocket_metrics': {
                'total_connections': websocket_stats.get('total_connections', 0),
                'active_tenant_connections': websocket_stats.get('active_tenants', 0),
                'connections_per_tenant': websocket_stats.get('connections_per_tenant', {})
            },
            'system_health': {
                'status': 'healthy',
                'uptime_hours': 0,  # This would come from system monitoring
                'last_updated': datetime.utcnow().isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get global initial stats: {e}")
        return {
            'system_overview': {},
            'request_metrics': {},
            'websocket_metrics': {},
            'system_health': {
                'status': 'error',
                'error': 'Failed to load global statistics',
                'last_updated': datetime.utcnow().isoformat()
            }
        }

async def get_tenant_current_stats(tenant_id: str) -> dict:
    """Get current statistics for a tenant"""
    # This would be similar to get_tenant_initial_stats but potentially
    # with more real-time data or cached results
    return await get_tenant_initial_stats(tenant_id)

def _calculate_duration(connected_at: str) -> Optional[float]:
    """Calculate connection duration in seconds"""
    try:
        if not connected_at:
            return None
        connect_time = datetime.fromisoformat(connected_at.replace('Z', '+00:00'))
        duration = (datetime.utcnow() - connect_time).total_seconds()
        return round(duration, 2)
    except Exception:
        return None