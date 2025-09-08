"""
Redis cache service for detection results

Provides intelligent caching of detection results based on confidence levels:
- High confidence (>0.9): Cache for 30 minutes
- Medium confidence (0.5-0.9): Cache for 5 minutes  
- Low confidence (<0.5): No caching

Uses SHA-256 hashing of normalized text for consistent cache keys.
"""
import hashlib
import json
import logging
from typing import Optional
from redis import Redis
from pydantic import BaseModel

from ..models.detection import DetectionResponseModel
from ..core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class CacheStats(BaseModel):
    """Cache statistics model"""
    hits: int = 0
    misses: int = 0
    errors: int = 0
    total_requests: int = 0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate"""
        if self.total_requests == 0:
            return 0.0
        return self.hits / self.total_requests


class DetectionCacheService:
    """Redis-based cache service for detection results"""
    
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.stats = CacheStats()
        
        # Cache configuration from settings
        self.enabled = settings.CACHE_ENABLED
        self.ttl_high_confidence = settings.CACHE_TTL_HIGH_CONFIDENCE
        self.ttl_medium_confidence = settings.CACHE_TTL_MEDIUM_CONFIDENCE
        self.ttl_low_confidence = settings.CACHE_TTL_LOW_CONFIDENCE
        self.high_confidence_threshold = settings.CACHE_HIGH_CONFIDENCE_THRESHOLD
        self.medium_confidence_threshold = settings.CACHE_MEDIUM_CONFIDENCE_THRESHOLD
        
        logger.info(f"Cache service initialized - Enabled: {self.enabled}")

    async def get_cached_result(self, text: str) -> Optional[DetectionResponseModel]:
        """
        Retrieve cached detection result for given text
        
        Args:
            text: Input text to check cache for
            
        Returns:
            Cached DetectionResponseModel if found, None otherwise
        """
        if not self.enabled:
            return None
            
        self.stats.total_requests += 1
        
        try:
            cache_key = self._generate_cache_key(text)
            cached_data = await self._get_from_redis(cache_key)
            
            if cached_data:
                # Deserialize cached result
                result_data = json.loads(cached_data)
                result = DetectionResponseModel(**result_data)
                
                self.stats.hits += 1
                logger.debug(f"Cache HIT for key: {cache_key[:16]}...")
                return result
            else:
                self.stats.misses += 1
                logger.debug(f"Cache MISS for key: {cache_key[:16]}...")
                return None
                
        except Exception as e:
            self.stats.errors += 1
            logger.error(f"Cache retrieval error: {e}")
            return None

    async def cache_result(self, text: str, result: DetectionResponseModel) -> bool:
        """
        Cache detection result based on confidence level
        
        Args:
            text: Original input text
            result: Detection result to cache
            
        Returns:
            True if successfully cached, False otherwise
        """
        if not self.enabled:
            return False
            
        try:
            # Determine TTL based on confidence
            ttl = self._get_ttl_for_confidence(result.confidence)
            
            # Don't cache low confidence results
            if ttl == 0:
                logger.debug(f"Not caching low confidence result: {result.confidence}")
                return False
                
            cache_key = self._generate_cache_key(text)
            
            # Serialize result to JSON
            cache_data = result.model_dump_json()
            
            # Store in Redis with TTL
            success = await self._set_in_redis(cache_key, cache_data, ttl)
            
            if success:
                logger.debug(f"Cached result for key: {cache_key[:16]}... (TTL: {ttl}s)")
            else:
                logger.warning(f"Failed to cache result for key: {cache_key[:16]}...")
                
            return success
            
        except Exception as e:
            self.stats.errors += 1
            logger.error(f"Cache storage error: {e}")
            return False

    def _generate_cache_key(self, text: str) -> str:
        """
        Generate consistent cache key from input text
        
        Args:
            text: Input text to generate key for
            
        Returns:
            SHA-256 hash-based cache key
        """
        # Normalize text for consistent hashing
        normalized_text = text.lower().strip()
        
        # Generate SHA-256 hash
        text_hash = hashlib.sha256(normalized_text.encode('utf-8')).hexdigest()
        
        # Create cache key with prefix
        return f"detection:{text_hash}"

    def _get_ttl_for_confidence(self, confidence: float) -> int:
        """
        Determine TTL based on confidence level
        
        Args:
            confidence: Detection confidence score (0.0-1.0)
            
        Returns:
            TTL in seconds
        """
        if confidence >= self.high_confidence_threshold:
            return self.ttl_high_confidence  # 30 minutes for high confidence
        elif confidence >= self.medium_confidence_threshold:
            return self.ttl_medium_confidence  # 5 minutes for medium confidence
        else:
            return self.ttl_low_confidence  # No caching for low confidence

    async def _get_from_redis(self, key: str) -> Optional[str]:
        """
        Get value from Redis (async wrapper)
        
        Args:
            key: Redis key
            
        Returns:
            Cached value as string, or None if not found
        """
        try:
            # Redis-py doesn't have native async, but we can use it in FastAPI
            # For true async, would need aioredis
            # Note: Redis client is configured with decode_responses=True, so value is already a string
            value = self.redis.get(key)
            return value if value else None
        except Exception as e:
            logger.error(f"Redis GET error for key {key}: {e}")
            return None

    async def _set_in_redis(self, key: str, value: str, ttl: int) -> bool:
        """
        Set value in Redis with TTL (async wrapper)
        
        Args:
            key: Redis key
            value: Value to store
            ttl: Time to live in seconds
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set value with expiration
            result = self.redis.setex(key, ttl, value)
            return bool(result)
        except Exception as e:
            logger.error(f"Redis SET error for key {key}: {e}")
            return False

    async def get_cache_stats(self) -> CacheStats:
        """Get current cache statistics"""
        return self.stats

    async def clear_cache(self) -> bool:
        """
        Clear all cached detection results
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Find all detection keys
            pattern = "detection:*"
            keys = self.redis.keys(pattern)
            
            if keys:
                deleted = self.redis.delete(*keys)
                logger.info(f"Cleared {deleted} cached detection results")
                return True
            else:
                logger.info("No cached detection results to clear")
                return True
                
        except Exception as e:
            logger.error(f"Cache clear error: {e}")
            return False

    async def get_cache_info(self) -> dict:
        """
        Get cache configuration and status information
        
        Returns:
            Dictionary with cache information
        """
        try:
            # Get Redis info
            redis_info = self.redis.info()
            
            return {
                "enabled": self.enabled,
                "redis_connected": True,
                "redis_memory_usage": redis_info.get("used_memory_human", "unknown"),
                "redis_keys": redis_info.get("db0", {}).get("keys", 0),
                "ttl_config": {
                    "high_confidence": f"{self.ttl_high_confidence}s",
                    "medium_confidence": f"{self.ttl_medium_confidence}s",
                    "low_confidence": f"{self.ttl_low_confidence}s"
                },
                "confidence_thresholds": {
                    "high": self.high_confidence_threshold,
                    "medium": self.medium_confidence_threshold
                },
                "stats": self.stats.model_dump()
            }
        except Exception as e:
            logger.error(f"Failed to get cache info: {e}")
            return {
                "enabled": self.enabled,
                "redis_connected": False,
                "error": str(e),
                "stats": self.stats.model_dump()
            }

    def reset_stats(self):
        """Reset cache statistics"""
        self.stats = CacheStats()
        logger.info("Cache statistics reset")