"""
Prometheus metrics for WebSocket functionality
"""

from prometheus_client import Counter, Histogram, Gauge

# WebSocket connection metrics
websocket_connections = Gauge(
    'websocket_active_connections_total',
    'Number of active WebSocket connections',
    ['tenant_id']
)

# WebSocket event metrics
websocket_events = Counter(
    'websocket_events_sent_total',
    'Total number of WebSocket events sent',
    ['event_type', 'tenant_id']
)

# WebSocket error metrics
websocket_errors = Counter(
    'websocket_errors_total',
    'Total number of WebSocket errors',
    ['error_type']
)

# WebSocket authentication metrics
websocket_auth_attempts = Counter(
    'websocket_auth_attempts_total',
    'Total WebSocket authentication attempts',
    ['status']  # success, failed_invalid_key, failed_missing_key
)

# WebSocket message processing time
websocket_processing_time = Histogram(
    'websocket_message_processing_seconds',
    'Time spent processing WebSocket messages',
    ['event_type']
)

# Rate limiting metrics
websocket_rate_limits = Counter(
    'websocket_rate_limit_hits_total',
    'Number of rate limit hits for WebSocket events',
    ['tenant_id']
)