"""
Data models for Prompt Shield SDK

Defines request/response models and configuration classes.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


@dataclass
class DetectionResult:
    """
    Result of a prompt injection detection request.
    
    Attributes:
        is_malicious: True if the text contains prompt injection attempts
        confidence: Confidence score from 0.0 to 1.0  
        threat_types: List of detected threat types
        processing_time_ms: Time taken for detection in milliseconds
        reason: Human-readable explanation of the detection result
        cache_hit: Whether the result was served from cache
        request_id: Unique identifier for the request (for debugging)
        detected_at: Timestamp when detection was performed
    """
    is_malicious: bool
    confidence: float
    threat_types: List[str] = field(default_factory=list)
    processing_time_ms: int = 0
    reason: str = ""
    cache_hit: bool = False
    request_id: str = ""
    detected_at: Optional[datetime] = None
    
    def __post_init__(self):
        """Set detected_at if not provided"""
        if self.detected_at is None:
            self.detected_at = datetime.utcnow()
    
    @property
    def is_safe(self) -> bool:
        """Convenience property - inverse of is_malicious"""
        return not self.is_malicious
    
    @property 
    def confidence_percentage(self) -> float:
        """Get confidence as percentage (0-100)"""
        return self.confidence * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            "is_malicious": self.is_malicious,
            "confidence": self.confidence, 
            "threat_types": self.threat_types,
            "processing_time_ms": self.processing_time_ms,
            "reason": self.reason,
            "cache_hit": self.cache_hit,
            "request_id": self.request_id,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None
        }
    
    @classmethod
    def from_api_response(cls, data: Dict[str, Any], cache_hit: bool = False, request_id: str = "") -> "DetectionResult":
        """Create DetectionResult from API response data"""
        return cls(
            is_malicious=data.get("is_malicious", False),
            confidence=data.get("confidence", 0.0),
            threat_types=data.get("threat_types", []),
            processing_time_ms=data.get("processing_time_ms", 0),
            reason=data.get("reason", ""),
            cache_hit=cache_hit,
            request_id=request_id
        )


@dataclass
class CacheConfig:
    """
    Configuration for client-side caching.
    
    Attributes:
        enabled: Whether caching is enabled
        ttl_seconds: Time-to-live for cache entries in seconds
        max_entries: Maximum number of entries to keep in memory cache
        redis_url: Redis URL for distributed caching (optional)
        key_prefix: Prefix for cache keys
    """
    enabled: bool = True
    ttl_seconds: int = 300  # 5 minutes default
    max_entries: int = 1000  # For in-memory cache
    redis_url: Optional[str] = None
    key_prefix: str = "prompt_shield:"
    
    def __post_init__(self):
        """Validate configuration"""
        if self.ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if self.max_entries <= 0:
            raise ValueError("max_entries must be positive")


@dataclass 
class RetryConfig:
    """
    Configuration for retry behavior.
    
    Attributes:
        max_retries: Maximum number of retry attempts
        base_delay: Base delay between retries in seconds
        max_delay: Maximum delay between retries in seconds
        exponential_base: Base for exponential backoff calculation
        jitter: Whether to add random jitter to delays
    """
    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    
    def __post_init__(self):
        """Validate retry configuration"""
        if self.max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if self.base_delay <= 0:
            raise ValueError("base_delay must be positive") 
        if self.max_delay <= 0:
            raise ValueError("max_delay must be positive")
        if self.exponential_base <= 1:
            raise ValueError("exponential_base must be greater than 1")


@dataclass
class ClientConfig:
    """
    Overall client configuration.
    
    Attributes:
        api_key: API key for authentication
        base_url: Base URL for the Prompt Shield API
        timeout: Request timeout in seconds
        user_agent: User agent string for requests
        cache_config: Cache configuration
        retry_config: Retry configuration  
        debug: Enable debug logging
    """
    api_key: str
    base_url: str = "https://api.prompt-shield.com"
    timeout: float = 30.0
    user_agent: str = f"prompt-shield-python/{__import__('prompt_shield').__version__}"
    cache_config: CacheConfig = field(default_factory=CacheConfig)
    retry_config: RetryConfig = field(default_factory=RetryConfig) 
    debug: bool = False
    
    def __post_init__(self):
        """Validate client configuration"""
        if not self.api_key:
            raise ValueError("api_key is required")
        if not self.base_url:
            raise ValueError("base_url is required")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        
        # Ensure base_url doesn't end with slash
        self.base_url = self.base_url.rstrip('/')


# Threat type constants for easier reference
class ThreatTypes:
    """Constants for common threat types"""
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak" 
    DATA_EXTRACTION = "data_extraction"
    ENCODING_ATTACK = "encoding_attack"
    ROLE_PLAYING = "role_playing"
    INSTRUCTION_OVERRIDE = "instruction_override"
    MALICIOUS_CODE = "malicious_code"
    
    @classmethod
    def all(cls) -> List[str]:
        """Get all threat type constants"""
        return [
            cls.JAILBREAK,
            cls.SYSTEM_PROMPT_LEAK,
            cls.DATA_EXTRACTION, 
            cls.ENCODING_ATTACK,
            cls.ROLE_PLAYING,
            cls.INSTRUCTION_OVERRIDE,
            cls.MALICIOUS_CODE,
        ]