"""
Real-time event definitions and data structures for WebSocket broadcasting
"""

from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional, Dict, Any, Union

class EventType(str, Enum):
    """WebSocket event types"""
    # Connection events
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    
    # Detection events
    NEW_DETECTION = "new_detection"
    BATCH_DETECTION = "batch_detection"
    
    # Metrics and analytics
    METRICS_UPDATE = "metrics_update"
    REALTIME_STATS = "realtime_stats"
    
    # System events
    SYSTEM_STATUS = "system_status"
    CACHE_STATS = "cache_stats"
    ERROR_ALERT = "error_alert"
    
    # Tenant-specific events
    RATE_LIMIT_WARNING = "rate_limit_warning"
    QUOTA_UPDATE = "quota_update"
    
    # Administrative events
    TENANT_UPDATE = "tenant_update"
    MAINTENANCE_NOTICE = "maintenance_notice"

class ThreatType(str, Enum):
    """Threat classification types"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXTRACTION = "data_extraction"
    SYSTEM_MANIPULATION = "system_manipulation"
    INSTRUCTION_OVERRIDE = "instruction_override"
    SOCIAL_ENGINEERING = "social_engineering"
    CODE_INJECTION = "code_injection"
    OTHER = "other"

class DetectionResult(BaseModel):
    """Detection result data structure"""
    model_config = {"protected_namespaces": ()}
    
    is_malicious: bool = Field(description="Whether the input was classified as malicious")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0-1")
    threat_types: List[ThreatType] = Field(default_factory=list, description="Detected threat types")
    model_used: str = Field(description="Which AI model was used for detection")
    processing_time_ms: float = Field(description="Processing time in milliseconds")
    cache_hit: bool = Field(default=False, description="Whether result came from cache")
    request_id: Optional[str] = Field(default=None, description="Unique request identifier")
    reason: Optional[str] = Field(default=None, description="Human-readable explanation")

class DetectionEvent(BaseModel):
    """New detection event"""
    event_type: EventType = EventType.NEW_DETECTION
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: str = Field(description="Tenant identifier")
    detection_result: DetectionResult = Field(description="Detection analysis results")
    input_metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata about the input")

class MetricsUpdate(BaseModel):
    """Metrics update event"""
    event_type: EventType = EventType.METRICS_UPDATE
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: str = Field(description="Tenant identifier")
    
    # Request metrics
    requests_last_minute: int = Field(ge=0, description="Requests in last minute")
    requests_last_hour: int = Field(ge=0, description="Requests in last hour")
    requests_today: int = Field(ge=0, description="Requests today")
    
    # Threat metrics
    threats_blocked_last_minute: int = Field(ge=0, description="Threats blocked in last minute")
    threats_blocked_today: int = Field(ge=0, description="Threats blocked today")
    threat_detection_rate: float = Field(ge=0.0, le=1.0, description="Percentage of malicious requests")
    
    # Performance metrics
    avg_response_time_ms: float = Field(ge=0, description="Average response time")
    p95_response_time_ms: float = Field(ge=0, description="95th percentile response time")
    cache_hit_rate: float = Field(ge=0.0, le=1.0, description="Cache hit rate percentage")
    
    # Top threat types in last hour
    top_threat_types: List[Dict[str, Union[str, int]]] = Field(
        default_factory=list, 
        description="Top threat types with counts"
    )

class SystemStatusEvent(BaseModel):
    """System status event"""
    event_type: EventType = EventType.SYSTEM_STATUS
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Overall system health
    status: str = Field(description="Overall system status: healthy, degraded, unhealthy")
    version: str = Field(description="System version")
    
    # Detection engine status
    detection_engine: Dict[str, Any] = Field(description="Detection engine health info")
    available_models: int = Field(ge=0, description="Number of available AI models")
    
    # Infrastructure status
    database_status: str = Field(description="Database connection status")
    redis_status: str = Field(description="Redis connection status")
    
    # Load information
    active_tenants: int = Field(ge=0, description="Number of active tenants")
    total_connections: int = Field(ge=0, description="Total WebSocket connections")
    requests_per_second: float = Field(ge=0, description="Current request rate")

class CacheStatsEvent(BaseModel):
    """Cache statistics event"""
    event_type: EventType = EventType.CACHE_STATS
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: str = Field(description="Tenant identifier")
    
    # Cache performance
    hit_rate: float = Field(ge=0.0, le=1.0, description="Cache hit rate")
    miss_rate: float = Field(ge=0.0, le=1.0, description="Cache miss rate")
    total_requests: int = Field(ge=0, description="Total cache requests")
    
    # Cache size and memory
    cached_items: int = Field(ge=0, description="Number of cached items")
    memory_usage_mb: float = Field(ge=0, description="Cache memory usage in MB")
    
    # Time-based stats
    hits_last_minute: int = Field(ge=0, description="Cache hits in last minute")
    misses_last_minute: int = Field(ge=0, description="Cache misses in last minute")

class ErrorAlertEvent(BaseModel):
    """Error alert event"""
    event_type: EventType = EventType.ERROR_ALERT
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: Optional[str] = Field(default=None, description="Tenant identifier (if applicable)")
    
    severity: str = Field(description="Error severity: critical, warning, info")
    error_type: str = Field(description="Type of error")
    message: str = Field(description="Human-readable error message")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional error details")
    
    # Context information
    endpoint: Optional[str] = Field(default=None, description="API endpoint involved")
    request_id: Optional[str] = Field(default=None, description="Request identifier")
    user_impact: str = Field(default="unknown", description="Impact on user experience")

class RateLimitWarningEvent(BaseModel):
    """Rate limit warning event"""
    event_type: EventType = EventType.RATE_LIMIT_WARNING
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: str = Field(description="Tenant identifier")
    
    current_rate: int = Field(description="Current request rate")
    limit: int = Field(description="Rate limit threshold")
    window_seconds: int = Field(description="Rate limit window in seconds")
    
    warning_threshold: float = Field(description="Percentage of limit when warning is triggered")
    reset_time: datetime = Field(description="When the rate limit window resets")
    
    recommended_action: str = Field(description="Suggested action to avoid rate limiting")

class TenantUpdateEvent(BaseModel):
    """Tenant configuration update event"""
    event_type: EventType = EventType.TENANT_UPDATE
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: str = Field(description="Tenant identifier")
    
    update_type: str = Field(description="Type of update: rate_limit, settings, status")
    changes: Dict[str, Any] = Field(description="What changed")
    previous_values: Dict[str, Any] = Field(default_factory=dict, description="Previous values")
    
    # Impact information
    requires_reconnection: bool = Field(default=False, description="Whether clients need to reconnect")
    effective_immediately: bool = Field(default=True, description="Whether changes are immediate")

# Union type for all possible events
WebSocketEvent = Union[
    DetectionEvent,
    MetricsUpdate,
    SystemStatusEvent,
    CacheStatsEvent,
    ErrorAlertEvent,
    RateLimitWarningEvent,
    TenantUpdateEvent
]

class EventBroadcaster:
    """Helper class to create and broadcast events"""
    
    @staticmethod
    async def broadcast_detection(tenant_id: str, detection_result: DetectionResult, 
                                input_text: str = "", request_id: str = ""):
        """Broadcast a new detection event"""
        from app.websocket.manager import manager
        
        event = DetectionEvent(
            tenant_id=tenant_id,
            detection_result=detection_result,
            input_metadata={
                "input_length": len(input_text),
                "request_id": request_id,
                "has_suspicious_patterns": detection_result.is_malicious
            }
        )
        
        await manager.broadcast_to_tenant(
            tenant_id=tenant_id,
            event=event.event_type.value,
            data=event.model_dump()
        )
    
    @staticmethod
    async def broadcast_metrics(tenant_id: str, metrics: Dict[str, Any]):
        """Broadcast metrics update"""
        from app.websocket.manager import manager
        
        event = MetricsUpdate(
            tenant_id=tenant_id,
            **metrics
        )
        
        await manager.broadcast_to_tenant(
            tenant_id=tenant_id,
            event=event.event_type.value,
            data=event.model_dump()
        )
    
    @staticmethod
    async def broadcast_error(tenant_id: Optional[str], severity: str, 
                            error_type: str, message: str, **kwargs):
        """Broadcast error alert"""
        from app.websocket.manager import manager
        
        event = ErrorAlertEvent(
            tenant_id=tenant_id,
            severity=severity,
            error_type=error_type,
            message=message,
            **kwargs
        )
        
        if tenant_id:
            await manager.broadcast_to_tenant(
                tenant_id=tenant_id,
                event=event.event_type.value,
                data=event.model_dump()
            )
        else:
            # Broadcast to all tenants if no specific tenant
            for tid in manager.tenant_connections.keys():
                await manager.broadcast_to_tenant(
                    tenant_id=tid,
                    event=event.event_type.value,
                    data=event.model_dump()
                )