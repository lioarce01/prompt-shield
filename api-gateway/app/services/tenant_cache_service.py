"""
Tenant-aware caching service
Redis-based caching with namespace isolation per tenant
"""

import json
import redis.asyncio as redis
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from app.core.config import get_settings

settings = get_settings()


class TenantCacheService:
    """Redis cache service with tenant namespace isolation"""
    
    def __init__(self, tenant_id: str):
        self.tenant_id = str(tenant_id)
        self.redis_client = None
        self._connect()
    
    def _connect(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                max_connections=20
            )
        except Exception as e:
            # Fallback to no-cache mode if Redis unavailable
            self.redis_client = None
    
    def _get_tenant_key(self, key: str) -> str:
        """Generate tenant-specific cache key"""
        return f"tenant:{self.tenant_id}:{key}"
    
    async def get_detection_result(self, text_hash: str) -> Optional[Dict[str, Any]]:
        """Get cached detection result for text hash"""
        if not self.redis_client:
            return None
        
        try:
            cache_key = self._get_tenant_key(f"detection:{text_hash}")
            cached_data = await self.redis_client.get(cache_key)
            
            if cached_data:
                result = json.loads(cached_data)
                # Update cache hit timestamp
                result['cached_at'] = datetime.utcnow().isoformat()
                return result
            
            return None
            
        except Exception:
            # If cache fails, continue without caching
            return None
    
    async def cache_detection_result(
        self, 
        text_hash: str, 
        result: Dict[str, Any], 
        ttl_seconds: int = 1800
    ) -> bool:
        """Cache detection result with TTL"""
        if not self.redis_client:
            return False
        
        try:
            cache_key = self._get_tenant_key(f"detection:{text_hash}")
            
            # Prepare cache data
            cache_data = {
                **result,
                'cached_at': datetime.utcnow().isoformat(),
                'ttl_seconds': ttl_seconds
            }
            
            # Store with expiration
            await self.redis_client.setex(
                cache_key, 
                ttl_seconds, 
                json.dumps(cache_data, default=str)
            )
            
            return True
            
        except Exception:
            return False
    
    async def invalidate_detection_cache(self, text_hash: str) -> bool:
        """Invalidate specific cached detection result"""
        if not self.redis_client:
            return False
        
        try:
            cache_key = self._get_tenant_key(f"detection:{text_hash}")
            result = await self.redis_client.delete(cache_key)
            return bool(result)
        except Exception:
            return False
    
    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for tenant"""
        if not self.redis_client:
            return {
                "status": "unavailable",
                "total_keys": 0,
                "estimated_memory_bytes": 0,
                "hit_rate_estimate": 0
            }
        
        try:
            # Get all tenant keys
            pattern = self._get_tenant_key("*")
            keys = await self.redis_client.keys(pattern)
            
            # Count by type
            detection_keys = [k for k in keys if ":detection:" in k]
            
            # Estimate memory usage (rough calculation)
            total_memory = 0
            if keys:
                # Sample a few keys to estimate average size
                sample_keys = keys[:min(10, len(keys))]
                for key in sample_keys:
                    try:
                        memory = await self.redis_client.memory_usage(key)
                        if memory:
                            total_memory += memory
                    except:
                        total_memory += 256  # Fallback estimate
                
                # Extrapolate to all keys
                if len(sample_keys) > 0:
                    avg_size = total_memory / len(sample_keys)
                    total_memory = int(avg_size * len(keys))
            
            return {
                "status": "healthy",
                "tenant_namespace": f"tenant:{self.tenant_id}",
                "total_keys": len(keys),
                "detection_cache_keys": len(detection_keys),
                "estimated_memory_bytes": total_memory,
                "redis_connection": "active"
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "total_keys": 0,
                "estimated_memory_bytes": 0
            }
    
    async def clear_tenant_cache(self) -> int:
        """Clear all cache entries for tenant"""
        if not self.redis_client:
            return 0
        
        try:
            pattern = self._get_tenant_key("*")
            keys = await self.redis_client.keys(pattern)
            
            if keys:
                deleted = await self.redis_client.delete(*keys)
                return deleted
            
            return 0
            
        except Exception:
            return 0
    
    async def set_tenant_setting(self, setting_key: str, value: Any, ttl_seconds: int = 3600) -> bool:
        """Cache tenant-specific settings"""
        if not self.redis_client:
            return False
        
        try:
            cache_key = self._get_tenant_key(f"setting:{setting_key}")
            await self.redis_client.setex(
                cache_key, 
                ttl_seconds, 
                json.dumps(value, default=str)
            )
            return True
        except Exception:
            return False
    
    async def get_tenant_setting(self, setting_key: str) -> Optional[Any]:
        """Get cached tenant-specific setting"""
        if not self.redis_client:
            return None
        
        try:
            cache_key = self._get_tenant_key(f"setting:{setting_key}")
            cached_data = await self.redis_client.get(cache_key)
            
            if cached_data:
                return json.loads(cached_data)
            
            return None
            
        except Exception:
            return None
    
    async def increment_counter(self, counter_name: str, window_seconds: int = 3600) -> int:
        """Increment a tenant-specific counter with expiration"""
        if not self.redis_client:
            return 1
        
        try:
            cache_key = self._get_tenant_key(f"counter:{counter_name}")
            
            # Use pipeline for atomic operations
            pipeline = self.redis_client.pipeline()
            pipeline.incr(cache_key)
            pipeline.expire(cache_key, window_seconds)
            
            results = await pipeline.execute()
            return results[0]  # Return the incremented value
            
        except Exception:
            return 1
    
    async def get_counter(self, counter_name: str) -> int:
        """Get current value of tenant-specific counter"""
        if not self.redis_client:
            return 0
        
        try:
            cache_key = self._get_tenant_key(f"counter:{counter_name}")
            value = await self.redis_client.get(cache_key)
            return int(value) if value else 0
        except Exception:
            return 0
    
    async def close(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()