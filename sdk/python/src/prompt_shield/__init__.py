"""
Prompt Shield Python SDK

Real-time prompt injection detection with enterprise-grade security.
"""

__version__ = "1.0.0"
__author__ = "Prompt Shield Team"
__email__ = "contact@prompt-shield.com"

from .client import PromptShieldClient
from .models import DetectionResult, CacheConfig
from .exceptions import (
    PromptShieldError,
    AuthenticationError,
    RateLimitError,
    ValidationError,
    APIError,
    TimeoutError as PromptShieldTimeoutError,
)

__all__ = [
    # Core client
    "PromptShieldClient",
    
    # Models
    "DetectionResult", 
    "CacheConfig",
    
    # Exceptions
    "PromptShieldError",
    "AuthenticationError", 
    "RateLimitError",
    "ValidationError",
    "APIError",
    "PromptShieldTimeoutError",
    
    # Metadata
    "__version__",
    "__author__", 
    "__email__",
]