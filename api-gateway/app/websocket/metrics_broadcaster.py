"""
Periodic metrics broadcaster for real-time dashboard updates
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any
import time

from app.websocket.manager import manager
from app.websocket.events import EventBroadcaster, MetricsUpdate
from app.websocket.circuit_breaker import metrics_circuit_breaker, CircuitBreakerOpenException

logger = logging.getLogger(__name__)

class MetricsBroadcaster:
    """Broadcasts periodic metrics updates to connected WebSocket clients"""
    
    def __init__(self):
        self.running = False
        self.interval = 5  # seconds
        self.task = None
        self._last_broadcast_time = {}  # tenant_id -> timestamp
        
    async def start(self):
        """Start the periodic metrics broadcasting"""
        if self.running:
            logger.warning("Metrics broadcaster is already running")
            return
            
        self.running = True
        self.task = asyncio.create_task(self._broadcast_loop())
        logger.info("Metrics broadcaster started", interval_seconds=self.interval)
    
    async def stop(self):
        """Stop the metrics broadcasting"""
        if not self.running:
            return
            
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        
        logger.info("Metrics broadcaster stopped")
    
    async def _broadcast_loop(self):
        """Main broadcasting loop"""
        while self.running:
            try:
                await self._broadcast_all_tenant_metrics()
                await asyncio.sleep(self.interval)
            except asyncio.CancelledError:
                logger.info("Metrics broadcaster loop cancelled")
                break
            except Exception as e:
                logger.error(f"Metrics broadcast error: {e}")
                # Short sleep before retrying
                await asyncio.sleep(1)
    
    async def _broadcast_all_tenant_metrics(self):
        """Broadcast metrics for all active tenants"""
        active_tenants = list(manager.tenant_connections.keys())
        
        if not active_tenants:
            logger.debug("No active tenants for metrics broadcast")
            return
        
        logger.debug(f"Broadcasting metrics to {len(active_tenants)} tenants")
        
        # Process each tenant
        broadcast_tasks = []
        for tenant_id in active_tenants:
            task = asyncio.create_task(
                self._broadcast_tenant_metrics(tenant_id)
            )
            broadcast_tasks.append(task)
        
        # Wait for all broadcasts to complete
        if broadcast_tasks:
            results = await asyncio.gather(*broadcast_tasks, return_exceptions=True)
            
            # Log any errors
            errors = [r for r in results if isinstance(r, Exception)]
            if errors:
                logger.warning(f"Metrics broadcast errors for {len(errors)} tenants")
    
    async def _broadcast_tenant_metrics(self, tenant_id: str):
        """Broadcast metrics for a specific tenant with circuit breaker protection"""
        try:
            await metrics_circuit_breaker.call(self._do_broadcast_metrics, tenant_id)
        except CircuitBreakerOpenException:
            logger.warning(f"Metrics circuit breaker is OPEN, skipping metrics for tenant {tenant_id}")
        except Exception as e:
            logger.error(f"Failed to broadcast metrics to tenant {tenant_id}: {e}")
    
    async def _do_broadcast_metrics(self, tenant_id: str):
        """Internal method to perform metrics broadcast"""
        # Get real-time metrics for the tenant
        metrics = await self._get_tenant_metrics(tenant_id)
        
        # Create metrics update event
        metrics_event = MetricsUpdate(
            tenant_id=tenant_id,
            **metrics
        )
        
        # Broadcast to tenant
        await manager.broadcast_to_tenant(
            tenant_id=tenant_id,
            event=metrics_event.event_type.value,
            data=metrics_event.model_dump()
        )
        
        # Update last broadcast time
        self._last_broadcast_time[tenant_id] = time.time()
        
        logger.debug(f"Metrics broadcasted to tenant {tenant_id}")
    
    async def _get_tenant_metrics(self, tenant_id: str) -> Dict[str, Any]:
        """Get current metrics for a tenant"""
        try:
            # Import here to avoid circular imports
            from app.services.tenant_analytics_service import TenantAnalyticsService
            from app.core.database import get_db_session
            
            async with get_db_session() as db:
                analytics_service = TenantAnalyticsService(db)
                
                # Get real-time metrics
                now = datetime.utcnow()
                
                # Requests in different time windows
                requests_last_minute = await analytics_service.get_request_count(
                    tenant_id, since=now - timedelta(minutes=1)
                )
                requests_last_hour = await analytics_service.get_request_count(
                    tenant_id, since=now - timedelta(hours=1)
                )
                requests_today = await analytics_service.get_request_count(
                    tenant_id, since=now.replace(hour=0, minute=0, second=0, microsecond=0)
                )
                
                # Threat metrics
                threats_last_minute = await analytics_service.get_threat_count(
                    tenant_id, since=now - timedelta(minutes=1)
                )
                threats_today = await analytics_service.get_threat_count(
                    tenant_id, since=now.replace(hour=0, minute=0, second=0, microsecond=0)
                )
                
                # Calculate threat detection rate
                threat_detection_rate = 0.0
                if requests_today > 0:
                    threat_detection_rate = threats_today / requests_today
                
                # Performance metrics
                performance_stats = await analytics_service.get_performance_stats(
                    tenant_id, since=now - timedelta(hours=1)
                )
                
                # Cache metrics
                from app.services.tenant_cache_service import TenantCacheService
                cache_service = TenantCacheService(tenant_id)
                cache_stats = await cache_service.get_cache_stats()
                
                # Top threat types
                top_threat_types = await analytics_service.get_top_threat_types(
                    tenant_id, since=now - timedelta(hours=1), limit=5
                )
                
                return {
                    "requests_last_minute": requests_last_minute,
                    "requests_last_hour": requests_last_hour,
                    "requests_today": requests_today,
                    "threats_blocked_last_minute": threats_last_minute,
                    "threats_blocked_today": threats_today,
                    "threat_detection_rate": round(threat_detection_rate, 3),
                    "avg_response_time_ms": performance_stats.get('avg_response_time', 0),
                    "p95_response_time_ms": performance_stats.get('p95_response_time', 0),
                    "cache_hit_rate": cache_stats.get('hit_rate', 0.0),
                    "top_threat_types": [
                        {"type": threat_type, "count": count} 
                        for threat_type, count in top_threat_types
                    ]
                }
                
        except Exception as e:
            logger.error(f"Failed to get metrics for tenant {tenant_id}: {e}")
            # Return default metrics if there's an error
            return {
                "requests_last_minute": 0,
                "requests_last_hour": 0,
                "requests_today": 0,
                "threats_blocked_last_minute": 0,
                "threats_blocked_today": 0,
                "threat_detection_rate": 0.0,
                "avg_response_time_ms": 0,
                "p95_response_time_ms": 0,
                "cache_hit_rate": 0.0,
                "top_threat_types": []
            }
    
    def get_status(self) -> Dict[str, Any]:
        """Get broadcaster status"""
        return {
            "running": self.running,
            "interval_seconds": self.interval,
            "active_tenants": len(self._last_broadcast_time),
            "last_broadcasts": dict(self._last_broadcast_time)
        }

# Global broadcaster instance
broadcaster = MetricsBroadcaster()

async def start_metrics_broadcaster():
    """Start the global metrics broadcaster"""
    await broadcaster.start()

async def stop_metrics_broadcaster():
    """Stop the global metrics broadcaster"""
    await broadcaster.stop()

def get_metrics_broadcaster_status() -> Dict[str, Any]:
    """Get status of the metrics broadcaster"""
    return broadcaster.get_status()