"""
WebSocket administration and monitoring endpoints
"""

import logging
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status
from app.core.tenant_auth import get_current_tenant
from app.models.tenant import Tenant

from app.websocket.manager import manager
from app.websocket.metrics_broadcaster import get_metrics_broadcaster_status
from app.websocket.circuit_breaker import get_circuit_breaker_status

router = APIRouter(prefix="/v1/websocket", tags=["WebSocket Management"])
logger = logging.getLogger(__name__)


@router.get("/status")
async def websocket_status(
    tenant: Tenant = Depends(get_current_tenant)
):
    """
    Get WebSocket connection status for the current tenant
    """
    tenant_id = str(tenant.id)
    connection_count = manager.get_tenant_connection_count(tenant_id)
    sessions = manager.get_tenant_sessions(tenant_id)
    
    # Get session details
    session_details = []
    for session_id in sessions:
        metadata = manager.get_session_metadata(session_id)
        if metadata:
            session_details.append({
                "session_id": session_id,
                "connected_at": metadata.get("connected_at"),
                "last_activity": metadata.get("last_activity")
            })
    
    return {
        "tenant_id": tenant_id,
        "tenant_name": tenant.name,
        "active_connections": connection_count,
        "session_details": session_details,
        "websocket_enabled": True,
        "last_updated": datetime.utcnow().isoformat()
    }


@router.get("/metrics")
async def websocket_metrics(
    tenant: Tenant = Depends(get_current_tenant)
):
    """
    Get WebSocket metrics for the current tenant
    """
    tenant_id = str(tenant.id)
    
    # Get general stats
    connection_count = manager.get_tenant_connection_count(tenant_id)
    
    # Get metrics broadcaster status
    broadcaster_status = get_metrics_broadcaster_status()
    
    return {
        "tenant_id": tenant_id,
        "metrics": {
            "active_connections": connection_count,
            "metrics_broadcaster": {
                "enabled": broadcaster_status.get("running", False),
                "interval_seconds": broadcaster_status.get("interval_seconds", 0),
                "last_broadcast": broadcaster_status.get("last_broadcasts", {}).get(tenant_id, "never")
            }
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/broadcast/test")
async def test_broadcast(
    tenant: Tenant = Depends(get_current_tenant)
):
    """
    Send a test broadcast to verify WebSocket functionality
    """
    tenant_id = str(tenant.id)
    connection_count = manager.get_tenant_connection_count(tenant_id)
    
    if connection_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active WebSocket connections for this tenant"
        )
    
    # Send test message
    test_data = {
        "message": "Test broadcast from API",
        "tenant_name": tenant.name,
        "timestamp": datetime.utcnow().isoformat(),
        "test": True
    }
    
    try:
        await manager.broadcast_to_tenant(
            tenant_id=tenant_id,
            event="test_message",
            data=test_data
        )
        
        logger.info(f"Test broadcast sent to tenant {tenant_id}")
        
        return {
            "success": True,
            "message": f"Test broadcast sent to {connection_count} connections",
            "tenant_id": tenant_id,
            "connections_notified": connection_count
        }
        
    except Exception as e:
        logger.error(f"Failed to send test broadcast to tenant {tenant_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send test broadcast: {str(e)}"
        )


@router.get("/admin/global-status")
async def global_websocket_status():
    """
    Get global WebSocket status (no tenant auth required - for system monitoring)
    """
    stats = manager.get_all_stats()
    broadcaster_status = get_metrics_broadcaster_status()
    circuit_breaker_status = get_circuit_breaker_status()
    
    return {
        "system_status": "operational",
        "global_stats": stats,
        "metrics_broadcaster": broadcaster_status,
        "circuit_breakers": circuit_breaker_status,
        "features": {
            "tenant_isolation": True,
            "metrics_broadcasting": True,
            "circuit_breaker_protection": True,
            "rate_limiting": True
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/admin/circuit-breakers")
async def circuit_breaker_status_endpoint():
    """
    Get detailed circuit breaker status for monitoring
    """
    return {
        "circuit_breakers": get_circuit_breaker_status(),
        "timestamp": datetime.utcnow().isoformat()
    }


@router.post("/admin/circuit-breakers/reset")
async def reset_circuit_breakers():
    """
    Reset all circuit breakers (for administrative purposes)
    """
    try:
        from app.websocket.circuit_breaker import (
            broadcast_circuit_breaker, 
            metrics_circuit_breaker, 
            auth_circuit_breaker
        )
        
        # Reset all circuit breakers to closed state
        for breaker in [broadcast_circuit_breaker, metrics_circuit_breaker, auth_circuit_breaker]:
            breaker._move_to_closed()
        
        logger.info("All WebSocket circuit breakers reset to CLOSED state")
        
        return {
            "success": True,
            "message": "All circuit breakers reset to CLOSED state",
            "circuit_breakers": get_circuit_breaker_status(),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to reset circuit breakers: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reset circuit breakers: {str(e)}"
        )