"""
Circuit breaker for WebSocket operations to ensure resilience
"""

import time
import logging
from enum import Enum
from typing import Callable, Any, Optional
import asyncio
from functools import wraps

from app.websocket.metrics import websocket_errors

logger = logging.getLogger(__name__)

class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery

class WebSocketCircuitBreaker:
    """Circuit breaker for WebSocket operations"""
    
    def __init__(self, 
                 failure_threshold: int = 5,
                 success_threshold: int = 3,
                 timeout: int = 60,
                 name: str = "websocket"):
        """
        Initialize circuit breaker
        
        Args:
            failure_threshold: Number of failures before opening circuit
            success_threshold: Number of successes needed to close circuit from half-open
            timeout: Seconds to wait before trying half-open
            name: Name for logging and metrics
        """
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout = timeout
        self.name = name
        
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = CircuitState.CLOSED
        
        logger.info(
            f"WebSocket circuit breaker '{name}' initialized",
            failure_threshold=failure_threshold,
            success_threshold=success_threshold,
            timeout=timeout
        )
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with circuit breaker protection
        
        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Function result
            
        Raises:
            CircuitBreakerOpenException: If circuit is open
        """
        # Check circuit state
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self._move_to_half_open()
            else:
                raise CircuitBreakerOpenException(
                    f"Circuit breaker '{self.name}' is OPEN"
                )
        
        try:
            # Execute the function
            result = await func(*args, **kwargs) if asyncio.iscoroutinefunction(func) else func(*args, **kwargs)
            
            # Record success
            self._record_success()
            return result
            
        except Exception as e:
            # Record failure
            self._record_failure()
            
            # Update metrics
            websocket_errors.labels(error_type=f"circuit_breaker_{self.name}").inc()
            
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset from OPEN to HALF_OPEN"""
        return (
            self.last_failure_time is not None and
            time.time() - self.last_failure_time > self.timeout
        )
    
    def _move_to_half_open(self):
        """Move circuit to HALF_OPEN state"""
        self.state = CircuitState.HALF_OPEN
        self.success_count = 0
        logger.info(f"Circuit breaker '{self.name}' moved to HALF_OPEN")
    
    def _record_success(self):
        """Record a successful operation"""
        self.failure_count = 0
        
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.success_threshold:
                self._move_to_closed()
    
    def _record_failure(self):
        """Record a failed operation"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.state == CircuitState.HALF_OPEN:
            self._move_to_open()
        elif (self.state == CircuitState.CLOSED and 
              self.failure_count >= self.failure_threshold):
            self._move_to_open()
    
    def _move_to_closed(self):
        """Move circuit to CLOSED (normal) state"""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        logger.info(f"Circuit breaker '{self.name}' moved to CLOSED")
    
    def _move_to_open(self):
        """Move circuit to OPEN (failing) state"""
        self.state = CircuitState.OPEN
        logger.warning(
            f"Circuit breaker '{self.name}' moved to OPEN",
            failure_count=self.failure_count,
            threshold=self.failure_threshold
        )
    
    def get_state(self) -> dict:
        """Get current circuit breaker state"""
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "failure_threshold": self.failure_threshold,
            "success_threshold": self.success_threshold,
            "last_failure_time": self.last_failure_time,
            "timeout": self.timeout
        }

class CircuitBreakerOpenException(Exception):
    """Exception raised when circuit breaker is open"""
    pass

def circuit_breaker(name: str = "default", 
                   failure_threshold: int = 5, 
                   success_threshold: int = 3,
                   timeout: int = 60):
    """
    Decorator to add circuit breaker protection to functions
    
    Args:
        name: Circuit breaker name
        failure_threshold: Failures before opening
        success_threshold: Successes to close from half-open
        timeout: Seconds before attempting half-open
    """
    # Create circuit breaker instance
    breaker = WebSocketCircuitBreaker(
        failure_threshold=failure_threshold,
        success_threshold=success_threshold,
        timeout=timeout,
        name=name
    )
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await breaker.call(func, *args, **kwargs)
        return wrapper
    return decorator

# Global circuit breakers for different WebSocket operations
broadcast_circuit_breaker = WebSocketCircuitBreaker(
    failure_threshold=10,
    success_threshold=5,
    timeout=30,
    name="broadcast"
)

metrics_circuit_breaker = WebSocketCircuitBreaker(
    failure_threshold=5,
    success_threshold=3,
    timeout=60,
    name="metrics"
)

auth_circuit_breaker = WebSocketCircuitBreaker(
    failure_threshold=15,
    success_threshold=5,
    timeout=120,
    name="auth"
)

def get_circuit_breaker_status() -> dict:
    """Get status of all circuit breakers"""
    return {
        "broadcast": broadcast_circuit_breaker.get_state(),
        "metrics": metrics_circuit_breaker.get_state(),
        "auth": auth_circuit_breaker.get_state()
    }