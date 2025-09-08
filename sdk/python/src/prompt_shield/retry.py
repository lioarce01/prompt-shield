"""
Retry management for Prompt Shield SDK

Provides intelligent retry logic with exponential backoff and jitter.
"""

import asyncio
import logging
import random
import time
from typing import Callable, TypeVar, Union, Any
from functools import wraps

from .models import RetryConfig
from .exceptions import (
    PromptShieldError,
    RateLimitError,
    NetworkError,
    TimeoutError as PromptShieldTimeoutError,
    ServiceUnavailableError,
)

logger = logging.getLogger(__name__)

T = TypeVar('T')


class RetryManager:
    """
    Manages retry logic for API requests with exponential backoff.
    
    Implements smart retry strategies based on error type:
    - Rate limits: Respect Retry-After headers
    - Network errors: Exponential backoff with jitter
    - Service unavailable: Exponential backoff
    - Other errors: No retry (fail fast)
    """
    
    def __init__(self, config: RetryConfig):
        self.config = config
        
        # Error types that should trigger retries
        self._retryable_exceptions = (
            RateLimitError,
            NetworkError, 
            PromptShieldTimeoutError,
            ServiceUnavailableError,
        )
        
        logger.debug("RetryManager initialized", extra={
            "max_retries": config.max_retries,
            "base_delay": config.base_delay,
            "max_delay": config.max_delay
        })
    
    def execute(self, func: Callable[[], T]) -> T:
        """
        Execute function with retry logic (synchronous).
        
        Args:
            func: Function to execute
            
        Returns:
            Function result
            
        Raises:
            PromptShieldError: If all retry attempts fail
        """
        last_exception = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                if attempt > 0:
                    logger.info(f"Retry attempt {attempt}/{self.config.max_retries}")
                
                return func()
                
            except Exception as e:
                last_exception = e
                
                # Check if error is retryable
                if not self._should_retry(e, attempt):
                    logger.debug(f"Not retrying error: {type(e).__name__}: {e}")
                    raise e
                
                # Calculate delay before next retry
                if attempt < self.config.max_retries:
                    delay = self._calculate_delay(e, attempt)
                    logger.info(f"Retrying in {delay:.2f} seconds", extra={
                        "attempt": attempt + 1,
                        "max_retries": self.config.max_retries,
                        "error": str(e)
                    })
                    time.sleep(delay)
        
        # All retries exhausted
        logger.error(f"All {self.config.max_retries} retry attempts failed")
        if last_exception:
            raise last_exception
        else:
            raise PromptShieldError("All retry attempts failed")
    
    async def execute_async(self, func: Callable[[], T]) -> T:
        """
        Execute async function with retry logic.
        
        Args:
            func: Async function to execute
            
        Returns:
            Function result
            
        Raises:
            PromptShieldError: If all retry attempts fail
        """
        last_exception = None
        
        for attempt in range(self.config.max_retries + 1):
            try:
                if attempt > 0:
                    logger.info(f"Retry attempt {attempt}/{self.config.max_retries}")
                
                return await func()
                
            except Exception as e:
                last_exception = e
                
                # Check if error is retryable
                if not self._should_retry(e, attempt):
                    logger.debug(f"Not retrying error: {type(e).__name__}: {e}")
                    raise e
                
                # Calculate delay before next retry
                if attempt < self.config.max_retries:
                    delay = self._calculate_delay(e, attempt)
                    logger.info(f"Retrying in {delay:.2f} seconds", extra={
                        "attempt": attempt + 1,
                        "max_retries": self.config.max_retries,
                        "error": str(e)
                    })
                    await asyncio.sleep(delay)
        
        # All retries exhausted
        logger.error(f"All {self.config.max_retries} retry attempts failed")
        if last_exception:
            raise last_exception
        else:
            raise PromptShieldError("All retry attempts failed")
    
    def _should_retry(self, exception: Exception, attempt: int) -> bool:
        """
        Determine if an exception should trigger a retry.
        
        Args:
            exception: The exception that occurred
            attempt: Current attempt number (0-based)
            
        Returns:
            True if should retry, False otherwise
        """
        # Don't retry if we've hit max attempts
        if attempt >= self.config.max_retries:
            return False
        
        # Check if exception type is retryable
        if not isinstance(exception, self._retryable_exceptions):
            return False
        
        # Special handling for rate limit errors
        if isinstance(exception, RateLimitError):
            # Always retry rate limit errors (up to max attempts)
            return True
        
        # Special handling for timeout errors
        if isinstance(exception, PromptShieldTimeoutError):
            # Retry timeouts, but be more conservative
            return attempt < min(2, self.config.max_retries)
        
        # Default: retry for retryable exceptions
        return True
    
    def _calculate_delay(self, exception: Exception, attempt: int) -> float:
        """
        Calculate delay before next retry attempt.
        
        Args:
            exception: The exception that occurred  
            attempt: Current attempt number (0-based)
            
        Returns:
            Delay in seconds
        """
        # Special handling for rate limit errors
        if isinstance(exception, RateLimitError):
            if hasattr(exception, 'retry_after') and exception.retry_after:
                # Respect Retry-After header, but cap at max_delay
                delay = min(float(exception.retry_after), self.config.max_delay)
                logger.debug(f"Using Retry-After delay: {delay}s")
                return delay
        
        # Exponential backoff calculation
        delay = self.config.base_delay * (self.config.exponential_base ** attempt)
        
        # Cap at maximum delay
        delay = min(delay, self.config.max_delay)
        
        # Add jitter to prevent thundering herd
        if self.config.jitter:
            jitter = random.uniform(0, delay * 0.1)  # Up to 10% jitter
            delay += jitter
        
        logger.debug(f"Calculated retry delay: {delay:.2f}s", extra={
            "attempt": attempt,
            "base_delay": self.config.base_delay,
            "exponential_base": self.config.exponential_base,
            "jitter": self.config.jitter
        })
        
        return delay


def with_retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True
):
    """
    Decorator to add retry logic to functions.
    
    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Base delay between retries
        max_delay: Maximum delay between retries
        exponential_base: Base for exponential backoff
        jitter: Whether to add jitter to delays
        
    Example:
        @with_retry(max_retries=3, base_delay=1.0)
        def make_api_call():
            # ... potentially failing API call
            pass
    """
    config = RetryConfig(
        max_retries=max_retries,
        base_delay=base_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
        jitter=jitter
    )
    
    retry_manager = RetryManager(config)
    
    def decorator(func):
        if asyncio.iscoroutinefunction(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                return await retry_manager.execute_async(
                    lambda: func(*args, **kwargs)
                )
            return async_wrapper
        else:
            @wraps(func) 
            def sync_wrapper(*args, **kwargs):
                return retry_manager.execute(
                    lambda: func(*args, **kwargs)
                )
            return sync_wrapper
    
    return decorator


class CircuitBreaker:
    """
    Circuit breaker pattern implementation for API calls.
    
    Prevents cascade failures by temporarily stopping requests
    to a failing service and allowing it to recover.
    
    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Service is failing, requests fail immediately  
    - HALF_OPEN: Testing if service has recovered
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = PromptShieldError
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self._failure_count = 0
        self._last_failure_time = None
        self._state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
        
        logger.debug("CircuitBreaker initialized", extra={
            "failure_threshold": failure_threshold,
            "recovery_timeout": recovery_timeout
        })
    
    def call(self, func: Callable[[], T]) -> T:
        """
        Execute function through circuit breaker (synchronous).
        
        Args:
            func: Function to execute
            
        Returns:
            Function result
            
        Raises:
            ServiceUnavailableError: If circuit is open
            Original exception: If function fails
        """
        if self._state == 'OPEN':
            if self._should_attempt_reset():
                self._state = 'HALF_OPEN'
                logger.info("Circuit breaker transitioning to HALF_OPEN")
            else:
                logger.debug("Circuit breaker is OPEN, failing fast")
                raise ServiceUnavailableError("Circuit breaker is OPEN")
        
        try:
            result = func()
            self._on_success()
            return result
            
        except self.expected_exception as e:
            self._on_failure()
            raise e
    
    async def call_async(self, func: Callable[[], T]) -> T:
        """
        Execute async function through circuit breaker.
        
        Args:
            func: Async function to execute
            
        Returns:
            Function result
            
        Raises:
            ServiceUnavailableError: If circuit is open
            Original exception: If function fails
        """
        if self._state == 'OPEN':
            if self._should_attempt_reset():
                self._state = 'HALF_OPEN'
                logger.info("Circuit breaker transitioning to HALF_OPEN")
            else:
                logger.debug("Circuit breaker is OPEN, failing fast")
                raise ServiceUnavailableError("Circuit breaker is OPEN")
        
        try:
            result = await func()
            self._on_success()
            return result
            
        except self.expected_exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if self._last_failure_time is None:
            return True
        
        return time.time() - self._last_failure_time > self.recovery_timeout
    
    def _on_success(self) -> None:
        """Handle successful request"""
        self._failure_count = 0
        if self._state == 'HALF_OPEN':
            self._state = 'CLOSED'
            logger.info("Circuit breaker reset to CLOSED")
    
    def _on_failure(self) -> None:
        """Handle failed request"""
        self._failure_count += 1
        self._last_failure_time = time.time()
        
        if self._failure_count >= self.failure_threshold:
            self._state = 'OPEN'
            logger.warning(f"Circuit breaker tripped to OPEN after {self._failure_count} failures")
    
    @property
    def state(self) -> str:
        """Get current circuit breaker state"""
        return self._state
    
    @property 
    def failure_count(self) -> int:
        """Get current failure count"""
        return self._failure_count