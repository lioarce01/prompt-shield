"""
WebSocket connection manager with tenant room isolation
"""

import logging
import time
from typing import Dict, Set, Optional
from collections import defaultdict, deque
from datetime import datetime

from app.websocket.socketio_server import get_socketio_server
from app.websocket.circuit_breaker import broadcast_circuit_breaker, CircuitBreakerOpenException

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiter for WebSocket events to prevent abuse"""
    
    def __init__(self, max_requests: int = 10, window: int = 60):
        self.max_requests = max_requests
        self.window = window
        self.requests: Dict[str, deque] = defaultdict(deque)
    
    def is_allowed(self, session_id: str) -> bool:
        """Check if session is allowed to send events"""
        now = time.time()
        session_requests = self.requests[session_id]
        
        # Remove old requests outside window
        while session_requests and session_requests[0] < now - self.window:
            session_requests.popleft()
        
        # Check if under limit
        if len(session_requests) < self.max_requests:
            session_requests.append(now)
            return True
        return False

class SocketManager:
    """Manages WebSocket connections with tenant isolation"""
    
    def __init__(self):
        self.tenant_connections: Dict[str, Set[str]] = {}  # tenant_id -> {session_ids}
        self.session_tenants: Dict[str, str] = {}          # session_id -> tenant_id
        self.session_metadata: Dict[str, Dict] = {}        # session_id -> metadata
        self.rate_limiter = RateLimiter(max_requests=20, window=60)  # 20 events per minute per session
        
    async def join_tenant_room(self, session_id: str, tenant_id: str, tenant_name: str = "", auth_context: dict = None):
        """Add session to tenant-specific room with authentication context"""
        sio = await get_socketio_server()
        room_name = f"tenant_{tenant_id}"
        
        await sio.enter_room(session_id, room_name)
        
        # Track connections
        if tenant_id not in self.tenant_connections:
            self.tenant_connections[tenant_id] = set()
        self.tenant_connections[tenant_id].add(session_id)
        self.session_tenants[session_id] = tenant_id
        
        # Store session metadata with auth context
        metadata = {
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "connected_at": datetime.utcnow().isoformat(),
            "last_activity": datetime.utcnow().isoformat()
        }
        
        # Add authentication context if provided
        if auth_context:
            metadata["auth_context"] = {
                "auth_method": auth_context.get("auth_method", "unknown"),
                "permissions": auth_context.get("permissions", {}),
                "rate_limits": auth_context.get("rate_limits", {}),
                "api_key_prefix": auth_context.get("api_key_prefix"),
                "authenticated_at": auth_context.get("authenticated_at")
            }
        
        self.session_metadata[session_id] = metadata
        
        auth_method = auth_context.get("auth_method", "unknown") if auth_context else "unknown"
        
        logger.info(f"Session {session_id} joined tenant room", 
                   tenant_id=tenant_id, 
                   tenant_name=tenant_name,
                   auth_method=auth_method,
                   total_connections=len(self.tenant_connections[tenant_id]))
        
        # Update metrics with auth method
        from app.websocket.metrics import websocket_connections
        websocket_connections.labels(tenant_id=tenant_id).inc()
    
    async def leave_tenant_room(self, session_id: str):
        """Remove session from tenant room"""
        tenant_id = self.session_tenants.get(session_id)
        if not tenant_id:
            return
        
        sio = await get_socketio_server()
        room_name = f"tenant_{tenant_id}"
        
        await sio.leave_room(session_id, room_name)
        
        # Clean up tracking
        if tenant_id in self.tenant_connections:
            self.tenant_connections[tenant_id].discard(session_id)
            # Remove empty tenant entries
            if not self.tenant_connections[tenant_id]:
                del self.tenant_connections[tenant_id]
        
        self.session_tenants.pop(session_id, None)
        self.session_metadata.pop(session_id, None)
        
        logger.info(f"Session {session_id} left tenant room", 
                   tenant_id=tenant_id,
                   remaining_connections=len(self.tenant_connections.get(tenant_id, [])))
        
        # Update metrics
        from app.websocket.metrics import websocket_connections
        websocket_connections.labels(tenant_id=tenant_id).dec()
    
    async def broadcast_to_tenant(self, tenant_id: str, event: str, data: dict):
        """Broadcast event to all sessions of a tenant with circuit breaker protection"""
        if tenant_id not in self.tenant_connections:
            logger.debug(f"No active connections for tenant {tenant_id}")
            return
        
        try:
            await broadcast_circuit_breaker.call(self._do_broadcast, tenant_id, event, data)
        except CircuitBreakerOpenException:
            logger.warning(f"Broadcast circuit breaker is OPEN, skipping broadcast to tenant {tenant_id}")
            # Don't raise exception - just skip the broadcast
        except Exception as e:
            logger.error(f"Failed to broadcast {event} to tenant {tenant_id}: {e}")
            from app.websocket.metrics import websocket_errors
            websocket_errors.labels(error_type=type(e).__name__).inc()
            # Don't re-raise - we don't want WebSocket failures to break the API
    
    async def _do_broadcast(self, tenant_id: str, event: str, data: dict):
        """Internal method to perform the actual broadcast"""
        sio = await get_socketio_server()
        room_name = f"tenant_{tenant_id}"
        
        # Add timestamp to all events
        data_with_timestamp = {
            **data,
            "timestamp": datetime.utcnow().isoformat(),
            "tenant_id": tenant_id
        }
        
        await sio.emit(event, data_with_timestamp, room=room_name)
        
        logger.debug(f"Broadcasted {event} to tenant {tenant_id}", 
                    active_connections=len(self.tenant_connections[tenant_id]))
        
        # Update metrics
        from app.websocket.metrics import websocket_events
        websocket_events.labels(event_type=event, tenant_id=tenant_id).inc()
    
    async def broadcast_to_session(self, session_id: str, event: str, data: dict):
        """Send event to specific session"""
        sio = await get_socketio_server()
        
        try:
            # Add timestamp to event
            data_with_timestamp = {
                **data,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            await sio.emit(event, data_with_timestamp, room=session_id)
            logger.debug(f"Sent {event} to session {session_id}")
            
        except Exception as e:
            logger.error(f"Failed to send {event} to session {session_id}: {e}")
            raise
    
    def get_tenant_connection_count(self, tenant_id: str) -> int:
        """Get number of active connections for a tenant"""
        return len(self.tenant_connections.get(tenant_id, set()))
    
    def get_session_metadata(self, session_id: str) -> Optional[Dict]:
        """Get metadata for a session"""
        return self.session_metadata.get(session_id)
    
    def update_session_activity(self, session_id: str):
        """Update last activity time for a session"""
        if session_id in self.session_metadata:
            self.session_metadata[session_id]["last_activity"] = datetime.utcnow().isoformat()
    
    def get_tenant_sessions(self, tenant_id: str) -> Set[str]:
        """Get all session IDs for a tenant"""
        return self.tenant_connections.get(tenant_id, set()).copy()
    
    def get_all_stats(self) -> Dict:
        """Get overall connection statistics"""
        total_connections = sum(len(sessions) for sessions in self.tenant_connections.values())
        return {
            "total_connections": total_connections,
            "active_tenants": len(self.tenant_connections),
            "connections_per_tenant": {
                tenant_id: len(sessions) 
                for tenant_id, sessions in self.tenant_connections.items()
            }
        }

# Global manager instance
manager = SocketManager()