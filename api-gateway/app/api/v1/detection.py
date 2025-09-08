"""
Tenant-Aware Detection API Endpoints
Multi-tenant implementation replacing single-tenant system
"""

import time
import uuid
import hashlib
from typing import Dict, Any
from datetime import datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from pydantic import Field
from app.core.base_model import BaseModel

from app.core.database import get_db
from app.core.tenant_auth import get_current_tenant, check_tenant_rate_limit
from app.models.tenant import Tenant, TenantRequest
from app.services.detection_service import DetectionService
from app.services.tenant_cache_service import TenantCacheService
from app.services.tenant_analytics_service import TenantAnalyticsService
from app.websocket.events import EventBroadcaster, DetectionResult, ThreatType

router = APIRouter(prefix="/v1", tags=["Detection"])
logger = structlog.get_logger()


# ===================================================
# PYDANTIC SCHEMAS
# ===================================================

class DetectionRequest(BaseModel):
    """Schema for detection request"""
    text: str = Field(..., min_length=1, max_length=10000, description="Text to analyze for prompt injection")


class DetectionResponse(BaseModel):
    """Schema for detection response"""
    is_malicious: bool
    confidence: float
    threat_types: list[str]
    processing_time_ms: float
    reason: str
    request_id: str
    cache_hit: bool = False
    model_used: str = None
    tenant_id: str
    
    # Metadata for analytics
    metadata: Dict[str, Any] = {}


# ===================================================
# DETECTION ENDPOINTS
# ===================================================

@router.post("/detect", response_model=DetectionResponse)
async def detect_prompt_injection(
    request: DetectionRequest,
    tenant: Tenant = Depends(check_tenant_rate_limit),  # This also validates tenant
    db: Session = Depends(get_db),
    http_request: Request = None
):
    """
    Detect prompt injection in text with tenant isolation
    
    Features:
    - Tenant-specific caching
    - Tenant-specific detection thresholds
    - Comprehensive request logging
    - Rate limiting per tenant
    """
    
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    logger.info(
        "Detection request received",
        tenant_id=str(tenant.id),
        tenant_name=tenant.name,
        request_id=request_id,
        text_length=len(request.text)
    )
    
    try:
        # Initialize services with tenant context
        cache_service = TenantCacheService(tenant.id)
        detection_service = DetectionService()
        analytics_service = TenantAnalyticsService(db)
        
        # Generate text hash for caching
        text_hash = hashlib.sha256(request.text.encode()).hexdigest()[:16]
        
        # Check cache first
        cached_result = await cache_service.get_detection_result(text_hash)
        if cached_result:
            processing_time = (time.time() - start_time) * 1000
            
            # Log cached request
            await analytics_service.log_request(
                tenant_id=tenant.id,
                request_id=request_id,
                text_length=len(request.text),
                text_hash=text_hash,
                result=cached_result,
                processing_time_ms=processing_time,
                cache_hit=True,
                user_agent=http_request.headers.get('User-Agent') if http_request else None,
                ip_address=http_request.client.host if http_request else None
            )
            
            logger.info(
                "Detection served from cache",
                tenant_id=str(tenant.id),
                request_id=request_id,
                processing_time_ms=processing_time
            )
            
            # Broadcast cache hit detection result via WebSocket
            try:
                detection_result_ws = DetectionResult(
                    is_malicious=cached_result['is_malicious'],
                    confidence=cached_result['confidence'],
                    threat_types=[ThreatType(t) for t in cached_result.get('threat_types', [])],
                    model_used=cached_result.get('model_used', 'cache'),
                    processing_time_ms=processing_time,
                    cache_hit=True,
                    request_id=request_id,
                    reason=cached_result.get('reason', 'Result served from cache')
                )
                
                await EventBroadcaster.broadcast_detection(
                    tenant_id=str(tenant.id),
                    detection_result=detection_result_ws,
                    input_text=request.text,
                    request_id=request_id
                )
            except Exception as ws_error:
                # Don't fail the request if WebSocket broadcast fails
                logger.warning(
                    "WebSocket broadcast failed for cached result",
                    tenant_id=str(tenant.id),
                    request_id=request_id,
                    error=str(ws_error)
                )
            
            return DetectionResponse(
                is_malicious=cached_result['is_malicious'],
                confidence=cached_result['confidence'],
                threat_types=cached_result['threat_types'],
                processing_time_ms=processing_time,
                reason=cached_result['reason'],
                request_id=request_id,
                cache_hit=True,
                model_used=cached_result.get('model_used'),
                tenant_id=str(tenant.id),
                metadata={
                    "cache_hit": True,
                    "tenant_settings": {
                        "threshold": tenant.detection_threshold,
                        "cache_enabled": tenant.settings.get('cache_enabled', True)
                    }
                }
            )
        
        # Perform detection with tenant-specific settings
        detection_result = await detection_service.detect_with_tenant_settings(
            text=request.text,
            tenant_settings={
                'detection_threshold': tenant.detection_threshold,
                'tenant_id': str(tenant.id)
            }
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        # Cache result if tenant has caching enabled
        if tenant.settings.get('cache_enabled', True):
            await cache_service.cache_detection_result(
                text_hash=text_hash,
                result=detection_result,
                ttl_seconds=1800  # 30 minutes
            )
        
        # Log request for analytics
        await analytics_service.log_request(
            tenant_id=tenant.id,
            request_id=request_id,
            text_length=len(request.text),
            text_hash=text_hash,
            result=detection_result,
            processing_time_ms=processing_time,
            cache_hit=False,
            user_agent=http_request.headers.get('User-Agent') if http_request else None,
            ip_address=http_request.client.host if http_request else None
        )
        
        # Send webhook notification if configured and malicious detected
        if (detection_result['is_malicious'] and 
            tenant.settings.get('webhook_url')):
            # TODO: Implement webhook notification in background
            pass
        
        logger.info(
            "Detection completed",
            tenant_id=str(tenant.id),
            request_id=request_id,
            is_malicious=detection_result['is_malicious'],
            confidence=detection_result['confidence'],
            processing_time_ms=processing_time,
            model_used=detection_result.get('model_used')
        )
        
        # Broadcast new detection result via WebSocket
        try:
            detection_result_ws = DetectionResult(
                is_malicious=detection_result['is_malicious'],
                confidence=detection_result['confidence'],
                threat_types=[ThreatType(t) for t in detection_result.get('threat_types', [])],
                model_used=detection_result.get('model_used', 'unknown'),
                processing_time_ms=processing_time,
                cache_hit=False,
                request_id=request_id,
                reason=detection_result.get('reason', 'New detection completed')
            )
            
            await EventBroadcaster.broadcast_detection(
                tenant_id=str(tenant.id),
                detection_result=detection_result_ws,
                input_text=request.text,
                request_id=request_id
            )
        except Exception as ws_error:
            # Don't fail the request if WebSocket broadcast fails
            logger.warning(
                "WebSocket broadcast failed for new detection",
                tenant_id=str(tenant.id),
                request_id=request_id,
                error=str(ws_error)
            )
        
        return DetectionResponse(
            is_malicious=detection_result['is_malicious'],
            confidence=detection_result['confidence'],
            threat_types=detection_result['threat_types'],
            processing_time_ms=processing_time,
            reason=detection_result['reason'],
            request_id=request_id,
            cache_hit=False,
            model_used=detection_result.get('model_used'),
            tenant_id=str(tenant.id),
            metadata={
                "cache_hit": False,
                "tenant_settings": {
                    "threshold": tenant.detection_threshold,
                    "cache_enabled": tenant.settings.get('cache_enabled', True)
                },
                "model_info": detection_result.get('model_info', {})
            }
        )
        
    except Exception as e:
        processing_time = (time.time() - start_time) * 1000
        
        logger.error(
            "Detection failed",
            tenant_id=str(tenant.id),
            request_id=request_id,
            error=str(e),
            processing_time_ms=processing_time
        )
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Detection service error",
                "request_id": request_id,
                "message": "An error occurred while processing your request"
            }
        )


@router.post("/detect/batch")
async def detect_batch_prompt_injection(
    requests: list[DetectionRequest],
    tenant: Tenant = Depends(check_tenant_rate_limit),
    db: Session = Depends(get_db)
):
    """
    Batch detection with tenant isolation
    Process multiple texts in a single request
    """
    
    if len(requests) > 100:  # Configurable limit
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Batch size too large. Maximum 100 requests per batch."
        )
    
    batch_id = str(uuid.uuid4())
    start_time = time.time()
    
    logger.info(
        "Batch detection started",
        tenant_id=str(tenant.id),
        batch_id=batch_id,
        batch_size=len(requests)
    )
    
    results = []
    
    try:
        for i, req in enumerate(requests):
            # Process each request individually
            result = await detect_prompt_injection(
                request=req,
                tenant=tenant,
                db=db
            )
            
            results.append(result)
        
        processing_time = (time.time() - start_time) * 1000
        
        logger.info(
            "Batch detection completed",
            tenant_id=str(tenant.id),
            batch_id=batch_id,
            batch_size=len(requests),
            processing_time_ms=processing_time
        )
        
        return {
            "batch_id": batch_id,
            "tenant_id": str(tenant.id),
            "total_requests": len(requests),
            "processing_time_ms": processing_time,
            "results": results,
            "summary": {
                "malicious_count": sum(1 for r in results if r.is_malicious),
                "safe_count": sum(1 for r in results if not r.is_malicious),
                "avg_confidence": sum(r.confidence for r in results) / len(results),
                "cache_hits": sum(1 for r in results if r.cache_hit)
            }
        }
        
    except Exception as e:
        logger.error(
            "Batch detection failed",
            tenant_id=str(tenant.id),
            batch_id=batch_id,
            error=str(e)
        )
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "Batch detection failed",
                "batch_id": batch_id,
                "completed_requests": len(results),
                "message": str(e)
            }
        )


# ===================================================
# HEALTH AND STATUS ENDPOINTS
# ===================================================

@router.get("/health")
async def health_check(
    tenant: Tenant = Depends(get_current_tenant)
):
    """
    Tenant-aware health check
    Verifies tenant status and service availability
    """
    
    return {
        "status": "healthy",
        "service": "prompt-shield-detection",
        "version": "2.0.0",
        "tenant": {
            "id": str(tenant.id),
            "name": tenant.name,
            "status": tenant.status,
            "settings": {
                "detection_threshold": tenant.detection_threshold,
                "rate_limit": tenant.rate_limit_per_minute,
                "cache_enabled": tenant.settings.get('cache_enabled', True)
            }
        },
        "detection_engine": {
            "status": "available",  # TODO: Check actual detection engine health
            "models_available": 4    # TODO: Get from detection service
        },
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/status")
async def detailed_status(
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """
    Detailed tenant status including recent activity
    """
    
    analytics_service = TenantAnalyticsService(db)
    cache_service = TenantCacheService(tenant.id)
    
    # Get recent activity summary
    recent_stats = await analytics_service.get_recent_stats(tenant.id, hours=24)
    
    # Get cache statistics
    cache_stats = await cache_service.get_cache_stats()
    
    return {
        "tenant": {
            "id": str(tenant.id),
            "name": tenant.name,
            "status": tenant.status,
            "created_at": tenant.created_at.isoformat()
        },
        "activity_24h": recent_stats,
        "cache": cache_stats,
        "limits": {
            "rate_limit_per_minute": tenant.rate_limit_per_minute,
            "detection_threshold": tenant.detection_threshold
        },
        "settings": tenant.settings,
        "system": {
            "detection_engine_status": "healthy",  # TODO: Actual check
            "cache_service_status": "healthy",
            "database_status": "healthy"
        }
    }