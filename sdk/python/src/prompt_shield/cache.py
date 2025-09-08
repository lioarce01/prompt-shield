"""
Cache management for Prompt Shield SDK

Provides in-memory and Redis-based caching for detection results.
"""

import logging
import pickle
import time
from typing import Optional, Dict, Any
from collections import OrderedDict

from .models import DetectionResult, CacheConfig
from .exceptions import CacheError

logger = logging.getLogger(__name__)


class InMemoryCache:
    """
    Simple in-memory LRU cache for detection results.
    
    Thread-safe implementation with automatic expiration.
    """
    
    def __init__(self, max_entries: int = 1000):
        self.max_entries = max_entries
        self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        
    def get(self, key: str) -> Optional[DetectionResult]:
        """Get cached result"""
        try:
            if key not in self._cache:
                return None
            
            entry = self._cache[key]
            
            # Check expiration
            if time.time() > entry['expires_at']:
                del self._cache[key]
                return None
            
            # Move to end (LRU)
            self._cache.move_to_end(key)
            
            return entry['result']
            
        except Exception as e:
            logger.warning(f"Cache get failed: {e}")
            return None
    
    def set(self, key: str, result: DetectionResult, ttl_seconds: int) -> bool:
        """Set cached result"""
        try:
            if ttl_seconds <= 0:
                return False
            
            # Remove expired entries periodically
            self._cleanup_expired()
            
            # Ensure cache size limit
            while len(self._cache) >= self.max_entries:
                self._cache.popitem(last=False)  # Remove oldest
            
            expires_at = time.time() + ttl_seconds
            self._cache[key] = {
                'result': result,
                'expires_at': expires_at
            }
            
            return True
            
        except Exception as e:
            logger.warning(f"Cache set failed: {e}")
            return False
    
    def _cleanup_expired(self) -> None:
        """Remove expired entries"""
        current_time = time.time()
        expired_keys = [
            key for key, entry in self._cache.items()
            if current_time > entry['expires_at']
        ]
        
        for key in expired_keys:
            del self._cache[key]
    
    def clear(self) -> None:
        """Clear all cached entries"""
        self._cache.clear()
    
    def size(self) -> int:
        """Get current cache size"""
        self._cleanup_expired()
        return len(self._cache)


class RedisCache:
    """
    Redis-based cache for detection results.
    
    Provides distributed caching across multiple client instances.
    """
    
    def __init__(self, redis_url: str, key_prefix: str = "prompt_shield:"):
        self.key_prefix = key_prefix
        self._redis = None
        
        try:
            import redis
            self._redis = redis.from_url(redis_url, decode_responses=False)
            # Test connection
            self._redis.ping()
            logger.info("Redis cache initialized", extra={"redis_url": redis_url})
        except ImportError:
            logger.error("Redis package not installed. Install with: pip install redis")
            raise CacheError("Redis package not installed")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            raise CacheError(f"Redis connection failed: {e}")
    
    def get(self, key: str) -> Optional[DetectionResult]:
        """Get cached result from Redis"""
        try:
            full_key = f"{self.key_prefix}{key}"
            data = self._redis.get(full_key)
            
            if data is None:
                return None
            
            # Deserialize result
            result = pickle.loads(data)
            
            if isinstance(result, DetectionResult):
                return result
            else:
                logger.warning(f"Invalid cached data type: {type(result)}")
                return None
                
        except Exception as e:
            logger.warning(f"Redis get failed: {e}")
            return None
    
    async def get_async(self, key: str) -> Optional[DetectionResult]:
        """Get cached result from Redis (async)"""
        try:
            import redis.asyncio as aioredis
            
            if not hasattr(self, '_async_redis'):
                # Create async Redis client on demand
                self._async_redis = aioredis.from_url(
                    self._redis.connection_pool.connection_kwargs.get('url', 'redis://localhost:6379'),
                    decode_responses=False
                )
            
            full_key = f"{self.key_prefix}{key}"
            data = await self._async_redis.get(full_key)
            
            if data is None:
                return None
            
            # Deserialize result
            result = pickle.loads(data)
            
            if isinstance(result, DetectionResult):
                return result
            else:
                logger.warning(f"Invalid cached data type: {type(result)}")
                return None
                
        except ImportError:
            logger.error("Redis asyncio package not available")
            return None
        except Exception as e:
            logger.warning(f"Redis async get failed: {e}")
            return None
    
    def set(self, key: str, result: DetectionResult, ttl_seconds: int) -> bool:
        """Set cached result in Redis"""
        try:
            if ttl_seconds <= 0:
                return False
            
            full_key = f"{self.key_prefix}{key}"
            data = pickle.dumps(result)
            
            success = self._redis.setex(full_key, ttl_seconds, data)
            return bool(success)
            
        except Exception as e:
            logger.warning(f"Redis set failed: {e}")
            return False
    
    async def set_async(self, key: str, result: DetectionResult, ttl_seconds: int) -> bool:
        """Set cached result in Redis (async)"""
        try:
            import redis.asyncio as aioredis
            
            if not hasattr(self, '_async_redis'):
                self._async_redis = aioredis.from_url(
                    self._redis.connection_pool.connection_kwargs.get('url', 'redis://localhost:6379'),
                    decode_responses=False
                )
            
            if ttl_seconds <= 0:
                return False
            
            full_key = f"{self.key_prefix}{key}"
            data = pickle.dumps(result)
            
            success = await self._async_redis.setex(full_key, ttl_seconds, data)
            return bool(success)
            
        except ImportError:
            logger.error("Redis asyncio package not available") 
            return False
        except Exception as e:
            logger.warning(f"Redis async set failed: {e}")
            return False
    
    def clear(self) -> None:
        """Clear all cached entries"""
        try:
            pattern = f"{self.key_prefix}*"
            keys = self._redis.keys(pattern)
            if keys:
                self._redis.delete(*keys)
        except Exception as e:
            logger.warning(f"Redis clear failed: {e}")


class CacheManager:
    """
    Main cache manager that handles both in-memory and Redis caching.
    
    Falls back to in-memory cache if Redis is unavailable.
    """
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self._memory_cache = InMemoryCache(config.max_entries)
        self._redis_cache = None
        
        # Initialize Redis cache if URL provided
        if config.redis_url:
            try:
                self._redis_cache = RedisCache(config.redis_url, config.key_prefix)
                logger.info("Using Redis cache")
            except CacheError as e:
                logger.warning(f"Redis cache initialization failed, using memory cache: {e}")
        else:
            logger.info("Using in-memory cache only")
    
    def get(self, key: str) -> Optional[DetectionResult]:
        """Get cached result (try Redis first, then memory)"""
        # Try Redis first if available
        if self._redis_cache:
            result = self._redis_cache.get(key)
            if result:
                return result
        
        # Fall back to memory cache
        return self._memory_cache.get(key)
    
    async def get_async(self, key: str) -> Optional[DetectionResult]:
        """Get cached result async (try Redis first, then memory)"""
        # Try Redis first if available
        if self._redis_cache:
            result = await self._redis_cache.get_async(key)
            if result:
                return result
        
        # Fall back to memory cache
        return self._memory_cache.get(key)
    
    def set(self, key: str, result: DetectionResult, ttl_seconds: int) -> bool:
        """Set cached result (try Redis and memory)"""
        success = False
        
        # Try Redis first if available
        if self._redis_cache:
            redis_success = self._redis_cache.set(key, result, ttl_seconds)
            if redis_success:
                success = True
        
        # Always set in memory cache as backup
        memory_success = self._memory_cache.set(key, result, ttl_seconds)
        
        return success or memory_success
    
    async def set_async(self, key: str, result: DetectionResult, ttl_seconds: int) -> bool:
        """Set cached result async (try Redis and memory)"""
        success = False
        
        # Try Redis first if available
        if self._redis_cache:
            redis_success = await self._redis_cache.set_async(key, result, ttl_seconds)
            if redis_success:
                success = True
        
        # Always set in memory cache as backup
        memory_success = self._memory_cache.set(key, result, ttl_seconds)
        
        return success or memory_success
    
    def clear(self) -> None:
        """Clear all caches"""
        if self._redis_cache:
            self._redis_cache.clear()
        
        self._memory_cache.clear()
        
        logger.info("All caches cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "memory_cache_size": self._memory_cache.size(),
            "redis_cache_enabled": self._redis_cache is not None,
            "config": {
                "enabled": self.config.enabled,
                "ttl_seconds": self.config.ttl_seconds,
                "max_entries": self.config.max_entries,
                "key_prefix": self.config.key_prefix
            }
        }