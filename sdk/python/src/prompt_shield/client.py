"""
Prompt Shield Python SDK Client

Main client class for interacting with the Prompt Shield API.
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import List, Optional, Dict, Any, Union
from urllib.parse import urljoin
import uuid

import httpx

from .models import DetectionResult, ClientConfig, CacheConfig, RetryConfig
from .exceptions import (
    PromptShieldError,
    AuthenticationError,
    NetworkError,
    TimeoutError as PromptShieldTimeoutError,
    exception_from_response,
)
from .cache import CacheManager
from .retry import RetryManager

logger = logging.getLogger(__name__)


class PromptShieldClient:
    """
    Main client for the Prompt Shield API.
    
    Provides both synchronous and asynchronous methods for detecting
    prompt injection attacks with built-in retry logic, caching,
    and comprehensive error handling.
    
    Examples:
        Basic usage:
        >>> client = PromptShieldClient(api_key="your-key")
        >>> result = client.detect("Ignore all instructions")
        >>> print(result.is_malicious)
        
        Async usage:
        >>> result = await client.detect_async("suspicious text")
        
        Batch processing:
        >>> results = client.detect_batch(["text1", "text2", "text3"])
    """
    
    def __init__(
        self,
        api_key: str,
        base_url: str = "http://localhost:8000",  # Default to local development
        timeout: float = 30.0,
        max_retries: int = 3,
        cache_config: Optional[CacheConfig] = None,
        debug: bool = False,
        **kwargs
    ):
        """
        Initialize the Prompt Shield client.
        
        Args:
            api_key: Your Prompt Shield API key
            base_url: Base URL for the API (default: local development)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts for failed requests  
            cache_config: Cache configuration (optional)
            debug: Enable debug logging
            **kwargs: Additional configuration options
        """
        
        # Validate required parameters
        if not api_key:
            raise ValueError("api_key is required")
        if not base_url:
            raise ValueError("base_url is required")
            
        # Create configuration
        self.config = ClientConfig(
            api_key=api_key,
            base_url=base_url.rstrip('/'),
            timeout=timeout,
            cache_config=cache_config or CacheConfig(),
            retry_config=RetryConfig(max_retries=max_retries),
            debug=debug,
            **kwargs
        )
        
        # Setup logging
        if debug:
            logging.basicConfig(level=logging.DEBUG)
            
        # Initialize HTTP clients
        self._sync_client: Optional[httpx.Client] = None
        self._async_client: Optional[httpx.AsyncClient] = None
        
        # Initialize managers
        self._cache_manager = CacheManager(self.config.cache_config) if self.config.cache_config.enabled else None
        self._retry_manager = RetryManager(self.config.retry_config)
        
        # Request headers
        self._headers = {
            "X-API-Key": self.config.api_key,
            "Content-Type": "application/json",
            "User-Agent": self.config.user_agent,
            "Accept": "application/json"
        }
        
        logger.info("PromptShieldClient initialized", extra={
            "base_url": self.config.base_url,
            "cache_enabled": self.config.cache_config.enabled,
            "max_retries": self.config.retry_config.max_retries
        })
    
    @property
    def sync_client(self) -> httpx.Client:
        """Get or create synchronous HTTP client"""
        if self._sync_client is None:
            self._sync_client = httpx.Client(
                timeout=self.config.timeout,
                headers=self._headers
            )
        return self._sync_client
    
    @property
    def async_client(self) -> httpx.AsyncClient:
        """Get or create asynchronous HTTP client"""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                timeout=self.config.timeout,
                headers=self._headers
            )
        return self._async_client
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        return str(uuid.uuid4())
    
    def _get_cache_key(self, text: str) -> str:
        """Generate cache key for text"""
        # Use SHA-256 hash of normalized text as cache key
        normalized_text = text.strip().lower()
        hash_object = hashlib.sha256(normalized_text.encode('utf-8'))
        return f"{self.config.cache_config.key_prefix}{hash_object.hexdigest()}"
    
    def detect(self, text: str) -> DetectionResult:
        """
        Detect prompt injection in text (synchronous).
        
        Args:
            text: Text to analyze for prompt injection
            
        Returns:
            DetectionResult with analysis results
            
        Raises:
            PromptShieldError: On API errors
            ValidationError: On invalid input
            AuthenticationError: On authentication failures
            RateLimitError: When rate limits are exceeded
            TimeoutError: On request timeout
        """
        if not text or not isinstance(text, str):
            from .exceptions import ValidationError
            raise ValidationError("Text must be a non-empty string")
            
        if len(text) > 10000:  # Match API gateway limit
            from .exceptions import ValidationError
            raise ValidationError("Text is too long (maximum 10,000 characters)")
        
        request_id = self._generate_request_id()
        
        # Check cache first
        if self._cache_manager:
            cache_key = self._get_cache_key(text)
            cached_result = self._cache_manager.get(cache_key)
            if cached_result:
                logger.debug("Cache hit", extra={"request_id": request_id, "cache_key": cache_key})
                cached_result.cache_hit = True
                cached_result.request_id = request_id
                return cached_result
        
        # Make API request with retry logic
        def make_request():
            return self._make_detect_request(text, request_id, sync=True)
        
        try:
            result = self._retry_manager.execute(make_request)
            
            # Cache successful result
            if self._cache_manager and result.confidence >= 0.5:  # Only cache confident results
                cache_key = self._get_cache_key(text)
                ttl = self._get_cache_ttl(result.confidence)
                self._cache_manager.set(cache_key, result, ttl)
                logger.debug("Result cached", extra={
                    "request_id": request_id, 
                    "cache_key": cache_key,
                    "ttl": ttl
                })
            
            return result
            
        except Exception as e:
            logger.error("Detection request failed", extra={
                "request_id": request_id,
                "error": str(e),
                "text_length": len(text)
            })
            raise
    
    async def detect_async(self, text: str) -> DetectionResult:
        """
        Detect prompt injection in text (asynchronous).
        
        Args:
            text: Text to analyze for prompt injection
            
        Returns:
            DetectionResult with analysis results
            
        Raises:
            Same exceptions as detect()
        """
        if not text or not isinstance(text, str):
            from .exceptions import ValidationError
            raise ValidationError("Text must be a non-empty string")
            
        if len(text) > 10000:
            from .exceptions import ValidationError
            raise ValidationError("Text is too long (maximum 10,000 characters)")
        
        request_id = self._generate_request_id()
        
        # Check cache first
        if self._cache_manager:
            cache_key = self._get_cache_key(text)
            cached_result = await self._cache_manager.get_async(cache_key)
            if cached_result:
                logger.debug("Cache hit", extra={"request_id": request_id, "cache_key": cache_key})
                cached_result.cache_hit = True
                cached_result.request_id = request_id
                return cached_result
        
        # Make API request with retry logic
        async def make_request():
            return await self._make_detect_request_async(text, request_id)
        
        try:
            result = await self._retry_manager.execute_async(make_request)
            
            # Cache successful result
            if self._cache_manager and result.confidence >= 0.5:
                cache_key = self._get_cache_key(text)
                ttl = self._get_cache_ttl(result.confidence)
                await self._cache_manager.set_async(cache_key, result, ttl)
                logger.debug("Result cached", extra={
                    "request_id": request_id,
                    "cache_key": cache_key, 
                    "ttl": ttl
                })
            
            return result
            
        except Exception as e:
            logger.error("Detection request failed", extra={
                "request_id": request_id,
                "error": str(e),
                "text_length": len(text)
            })
            raise
    
    def detect_batch(self, texts: List[str]) -> List[DetectionResult]:
        """
        Detect prompt injection in multiple texts (synchronous).
        
        Args:
            texts: List of texts to analyze
            
        Returns:
            List of DetectionResult objects (same order as input)
            
        Raises:
            ValidationError: On invalid input
            Other exceptions same as detect()
        """
        if not texts or not isinstance(texts, list):
            from .exceptions import ValidationError
            raise ValidationError("texts must be a non-empty list")
            
        if len(texts) > 100:  # Match API gateway batch limit
            from .exceptions import ValidationError
            raise ValidationError("Batch size too large (maximum 100 texts)")
        
        # Validate individual texts
        for i, text in enumerate(texts):
            if not text or not isinstance(text, str):
                from .exceptions import ValidationError
                raise ValidationError(f"Text at index {i} must be a non-empty string")
            if len(text) > 10000:
                from .exceptions import ValidationError
                raise ValidationError(f"Text at index {i} is too long (maximum 10,000 characters)")
        
        request_id = self._generate_request_id()
        
        # For batch requests, we'll process each text individually
        # This allows us to use caching and provides better error isolation
        results = []
        
        for text in texts:
            try:
                result = self.detect(text)
                results.append(result)
            except Exception as e:
                # Create error result for failed detection
                error_result = DetectionResult(
                    is_malicious=False,  # Default to safe on error
                    confidence=0.0,
                    reason=f"Detection failed: {str(e)}",
                    request_id=request_id
                )
                results.append(error_result)
                logger.warning("Batch item failed", extra={
                    "request_id": request_id,
                    "text_index": len(results) - 1,
                    "error": str(e)
                })
        
        return results
    
    async def detect_batch_async(self, texts: List[str]) -> List[DetectionResult]:
        """
        Detect prompt injection in multiple texts (asynchronous).
        
        Args:
            texts: List of texts to analyze
            
        Returns:
            List of DetectionResult objects (same order as input)
            
        Raises:
            Same exceptions as detect_batch()
        """
        if not texts or not isinstance(texts, list):
            from .exceptions import ValidationError
            raise ValidationError("texts must be a non-empty list")
            
        if len(texts) > 100:
            from .exceptions import ValidationError
            raise ValidationError("Batch size too large (maximum 100 texts)")
        
        # Validate individual texts
        for i, text in enumerate(texts):
            if not text or not isinstance(text, str):
                from .exceptions import ValidationError
                raise ValidationError(f"Text at index {i} must be a non-empty string")
            if len(text) > 10000:
                from .exceptions import ValidationError
                raise ValidationError(f"Text at index {i} is too long (maximum 10,000 characters)")
        
        request_id = self._generate_request_id()
        
        # Process all texts concurrently
        tasks = [self.detect_async(text) for text in texts]
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Convert exceptions to error results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    error_result = DetectionResult(
                        is_malicious=False,  # Default to safe on error
                        confidence=0.0,
                        reason=f"Detection failed: {str(result)}",
                        request_id=request_id
                    )
                    processed_results.append(error_result)
                    logger.warning("Batch item failed", extra={
                        "request_id": request_id,
                        "text_index": i,
                        "error": str(result)
                    })
                else:
                    processed_results.append(result)
            
            return processed_results
            
        except Exception as e:
            logger.error("Batch detection failed", extra={
                "request_id": request_id,
                "batch_size": len(texts),
                "error": str(e)
            })
            raise
    
    def _make_detect_request(self, text: str, request_id: str, sync: bool = True) -> DetectionResult:
        """Make synchronous detection request"""
        url = urljoin(self.config.base_url, "/v1/detect")
        payload = {"text": text}
        
        headers = self._headers.copy()
        headers["X-Request-ID"] = request_id
        
        start_time = time.time()
        
        try:
            response = self.sync_client.post(url, json=payload, headers=headers)
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            logger.debug("API request completed", extra={
                "request_id": request_id,
                "status_code": response.status_code,
                "processing_time_ms": processing_time_ms
            })
            
            if response.status_code == 200:
                data = response.json()
                result = DetectionResult.from_api_response(
                    data, 
                    cache_hit=False,
                    request_id=request_id
                )
                # Override processing time with actual measured time
                result.processing_time_ms = processing_time_ms
                return result
            else:
                raise exception_from_response(
                    response.status_code,
                    response.text,
                    dict(response.headers)
                )
                
        except httpx.TimeoutException:
            raise PromptShieldTimeoutError(
                f"Request timed out after {self.config.timeout} seconds",
                timeout_seconds=self.config.timeout,
                request_id=request_id
            )
        except httpx.NetworkError as e:
            raise NetworkError(f"Network error: {str(e)}", request_id=request_id)
    
    async def _make_detect_request_async(self, text: str, request_id: str) -> DetectionResult:
        """Make asynchronous detection request"""
        url = urljoin(self.config.base_url, "/v1/detect")
        payload = {"text": text}
        
        headers = self._headers.copy()
        headers["X-Request-ID"] = request_id
        
        start_time = time.time()
        
        try:
            response = await self.async_client.post(url, json=payload, headers=headers)
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            logger.debug("API request completed", extra={
                "request_id": request_id,
                "status_code": response.status_code, 
                "processing_time_ms": processing_time_ms
            })
            
            if response.status_code == 200:
                data = response.json()
                result = DetectionResult.from_api_response(
                    data,
                    cache_hit=False,
                    request_id=request_id
                )
                # Override processing time with actual measured time
                result.processing_time_ms = processing_time_ms
                return result
            else:
                raise exception_from_response(
                    response.status_code,
                    response.text,
                    dict(response.headers)
                )
                
        except httpx.TimeoutException:
            raise PromptShieldTimeoutError(
                f"Request timed out after {self.config.timeout} seconds",
                timeout_seconds=self.config.timeout,
                request_id=request_id
            )
        except httpx.NetworkError as e:
            raise NetworkError(f"Network error: {str(e)}", request_id=request_id)
    
    def _get_cache_ttl(self, confidence: float) -> int:
        """Get cache TTL based on confidence score"""
        if confidence >= 0.9:
            return self.config.cache_config.ttl_seconds * 6  # High confidence: 30 min
        elif confidence >= 0.5:
            return self.config.cache_config.ttl_seconds  # Medium confidence: 5 min
        else:
            return 0  # Low confidence: no caching
    
    def close(self) -> None:
        """Close HTTP clients and cleanup resources"""
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None
            
        if self._async_client:
            # For async client, we can't close it in sync method
            logger.warning("Async client should be closed using 'await client.aclose()'")
            
        logger.info("PromptShieldClient closed")
    
    async def aclose(self) -> None:
        """Close HTTP clients and cleanup resources (async)"""
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None
            
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None
            
        logger.info("PromptShieldClient closed (async)")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.aclose()
    
    def __repr__(self) -> str:
        """String representation"""
        return f"PromptShieldClient(base_url='{self.config.base_url}', cache_enabled={self.config.cache_config.enabled})"