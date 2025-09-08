"""
Custom exceptions for Prompt Shield SDK

Provides detailed, actionable error information for different failure scenarios.
"""

from typing import Optional, Dict, Any


class PromptShieldError(Exception):
    """
    Base exception for all Prompt Shield SDK errors.
    
    Attributes:
        message: Human-readable error message
        error_code: Machine-readable error code
        details: Additional error details
        request_id: Request ID for debugging (if available)
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None
    ):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.request_id = request_id
        super().__init__(self.message)
    
    def __str__(self) -> str:
        parts = [self.message]
        
        if self.error_code:
            parts.append(f"Error Code: {self.error_code}")
            
        if self.request_id:
            parts.append(f"Request ID: {self.request_id}")
            
        return " | ".join(parts)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary representation"""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "details": self.details,
            "request_id": self.request_id
        }


class AuthenticationError(PromptShieldError):
    """
    Raised when API key authentication fails.
    
    This usually means:
    - Invalid or missing API key
    - API key has been revoked or suspended
    - API key doesn't have permission for the requested operation
    """
    
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(message, error_code="AUTHENTICATION_FAILED", **kwargs)


class AuthorizationError(PromptShieldError):
    """
    Raised when the authenticated user doesn't have permission for the operation.
    
    This is different from AuthenticationError - the user is authenticated
    but doesn't have the required permissions.
    """
    
    def __init__(self, message: str = "Insufficient permissions", **kwargs):
        super().__init__(message, error_code="INSUFFICIENT_PERMISSIONS", **kwargs)


class RateLimitError(PromptShieldError):
    """
    Raised when rate limits are exceeded.
    
    Attributes:
        retry_after: Seconds to wait before retrying
        limit_type: Type of rate limit hit ('minute' or 'day')
        current_usage: Current usage count
        limit: The rate limit threshold
    """
    
    def __init__(
        self, 
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        limit_type: Optional[str] = None,
        current_usage: Optional[int] = None, 
        limit: Optional[int] = None,
        **kwargs
    ):
        self.retry_after = retry_after
        self.limit_type = limit_type
        self.current_usage = current_usage
        self.limit = limit
        
        # Add rate limit details to the main details dict
        details = kwargs.get('details', {})
        details.update({
            'retry_after': retry_after,
            'limit_type': limit_type, 
            'current_usage': current_usage,
            'limit': limit
        })
        kwargs['details'] = details
        
        super().__init__(message, error_code="RATE_LIMIT_EXCEEDED", **kwargs)


class ValidationError(PromptShieldError):
    """
    Raised when request validation fails.
    
    This includes:
    - Invalid input parameters
    - Text too long
    - Invalid batch size
    - Malformed requests
    """
    
    def __init__(self, message: str = "Validation failed", **kwargs):
        super().__init__(message, error_code="VALIDATION_ERROR", **kwargs)


class TimeoutError(PromptShieldError):
    """
    Raised when a request times out.
    
    Attributes:
        timeout_seconds: The timeout value that was exceeded
    """
    
    def __init__(
        self, 
        message: str = "Request timed out", 
        timeout_seconds: Optional[float] = None,
        **kwargs
    ):
        self.timeout_seconds = timeout_seconds
        
        details = kwargs.get('details', {})
        details['timeout_seconds'] = timeout_seconds
        kwargs['details'] = details
        
        super().__init__(message, error_code="REQUEST_TIMEOUT", **kwargs)


class APIError(PromptShieldError):
    """
    Raised for general API errors.
    
    Attributes:
        status_code: HTTP status code
        response_body: Raw response body (if available)
    """
    
    def __init__(
        self, 
        message: str = "API request failed",
        status_code: Optional[int] = None,
        response_body: Optional[str] = None,
        **kwargs
    ):
        self.status_code = status_code
        self.response_body = response_body
        
        details = kwargs.get('details', {})
        details.update({
            'status_code': status_code,
            'response_body': response_body
        })
        kwargs['details'] = details
        
        super().__init__(message, error_code="API_ERROR", **kwargs)


class NetworkError(PromptShieldError):
    """
    Raised when network connectivity issues occur.
    
    This includes:
    - Connection refused
    - DNS resolution failures
    - Network unreachable
    - SSL/TLS errors
    """
    
    def __init__(self, message: str = "Network error occurred", **kwargs):
        super().__init__(message, error_code="NETWORK_ERROR", **kwargs)


class ServiceUnavailableError(PromptShieldError):
    """
    Raised when the Prompt Shield service is temporarily unavailable.
    
    This usually indicates:
    - Service is under maintenance  
    - Service is experiencing high load
    - Temporary service outage
    
    Clients should implement retry logic for this error.
    """
    
    def __init__(self, message: str = "Service temporarily unavailable", **kwargs):
        super().__init__(message, error_code="SERVICE_UNAVAILABLE", **kwargs)


class CacheError(PromptShieldError):
    """
    Raised when cache operations fail.
    
    This is typically a non-fatal error - the SDK should fall back
    to making API requests without caching.
    """
    
    def __init__(self, message: str = "Cache operation failed", **kwargs):
        super().__init__(message, error_code="CACHE_ERROR", **kwargs)


# Exception mapping for HTTP status codes
STATUS_CODE_EXCEPTIONS = {
    400: ValidationError,
    401: AuthenticationError, 
    403: AuthorizationError,
    429: RateLimitError,
    500: APIError,
    502: ServiceUnavailableError,
    503: ServiceUnavailableError,
    504: TimeoutError,
}


def exception_from_response(status_code: int, response_body: str, headers: Dict[str, str]) -> PromptShieldError:
    """
    Create appropriate exception from HTTP response.
    
    Args:
        status_code: HTTP status code
        response_body: Response body text
        headers: Response headers
        
    Returns:
        Appropriate PromptShieldError subclass
    """
    
    # Try to parse error details from response
    error_details = {}
    request_id = headers.get('x-request-id') or headers.get('x-correlation-id')
    
    try:
        import json
        body_json = json.loads(response_body)
        if isinstance(body_json, dict):
            error_details = body_json.get('details', {})
    except (json.JSONDecodeError, AttributeError):
        pass
    
    # Get exception class for status code
    exception_class = STATUS_CODE_EXCEPTIONS.get(status_code, APIError)
    
    # Handle specific cases
    if status_code == 429:
        # Parse rate limit headers
        retry_after = None
        if 'retry-after' in headers:
            try:
                retry_after = int(headers['retry-after'])
            except ValueError:
                pass
                
        return RateLimitError(
            message="Rate limit exceeded",
            retry_after=retry_after,
            status_code=status_code,
            response_body=response_body,
            details=error_details,
            request_id=request_id
        )
    
    # Default case
    message = f"HTTP {status_code}: {response_body[:200]}..." if len(response_body) > 200 else f"HTTP {status_code}: {response_body}"
    
    return exception_class(
        message=message,
        status_code=status_code,
        response_body=response_body,
        details=error_details,
        request_id=request_id
    )