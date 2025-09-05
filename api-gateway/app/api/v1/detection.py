"""
Detection API endpoints

Core endpoints for prompt injection detection including:
- Single text analysis
- Batch processing 
- Async detection with webhooks
- System diagnostics and metrics
"""
import time
import uuid
from typing import Dict, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.openapi import get_openapi_examples
from app.core.security import APIKeyInfo
from app.api.dependencies import get_current_api_key, get_database
from app.models.detection import (
    SingleDetectionRequest,
    DetectionResponseModel,
    BatchDetectionRequest,
    BatchDetectionResponse,
    AsyncDetectionRequest,
    AsyncDetectionResponse
)
from app.models.auth import UsageLog
from app.services.detection_client import DetectionClient
from app.utils.validators import validate_text_safety

logger = structlog.get_logger()
router = APIRouter()
settings = get_settings()


def get_detection_client(request: Request) -> DetectionClient:
    """Dependency to get detection client from app state"""
    return request.app.state.detection_client


@router.post(
    "/detect", 
    response_model=DetectionResponseModel,
    responses={
        200: {
            "description": "Detection completed successfully",
            "content": {
                "application/json": {
                    "examples": {
                        "safe_text": {
                            "summary": "Safe text result",
                            "value": {
                                "is_malicious": False,
                                "confidence": 0.05,
                                "threat_types": [],
                                "processing_time_ms": 42,
                                "reason": "Text appears to be safe - no injection patterns detected",
                                "endpoint": "gemini",
                                "request_id": "req_abc123"
                            }
                        },
                        "malicious_text": {
                            "summary": "Malicious text result", 
                            "value": {
                                "is_malicious": True,
                                "confidence": 0.92,
                                "threat_types": ["jailbreak", "system_prompt_leak"],
                                "processing_time_ms": 67,
                                "reason": "Detected jailbreak attempt with system prompt extraction patterns",
                                "endpoint": "gemini",
                                "request_id": "req_def456"
                            }
                        }
                    }
                }
            }
        },
        400: {"$ref": "#/components/responses/ValidationError"},
        401: {"$ref": "#/components/responses/AuthenticationError"},
        429: {"$ref": "#/components/responses/RateLimitError"},
        503: {"$ref": "#/components/responses/ServerError"}
    },
    summary="Analyze text for prompt injection",
    description="**Primary detection endpoint** - Analyzes text using multiple AI models for real-time prompt injection detection with <50ms latency."
)
async def detect_prompt_injection(
    request: SingleDetectionRequest,
    http_request: Request,
    client: DetectionClient = Depends(get_detection_client),
    api_key_info: APIKeyInfo = Depends(get_current_api_key),
    db = Depends(get_database)
) -> DetectionResponseModel:
    """
    Analyze text for prompt injection attacks
    
    **Primary detection endpoint** - analyzes text using multiple AI models
    for real-time prompt injection detection with <50ms latency.
    
    **Detection Methods:**
    - ProtectAI DeBERTa v3 (specialized classifier)
    - Meta Llama Prompt Guard 2-86M (lightweight detection)
    - Google Gemini 2.0 Flash (advanced semantic analysis)
    
    **Threat Types Detected:**
    - Jailbreak attempts
    - System prompt leaks
    - Data extraction attempts
    - Injection attacks
    - Encoding attacks (Base64, Hex, etc.)
    - Delimiter attacks
    """
    request_start = time.time()
    request_id = str(uuid.uuid4())
    
    logger.info(
        "Processing detection request",
        request_id=request_id,
        text_length=len(request.text),
        confidence_threshold=request.config.confidence_threshold if request.config else 0.6
    )
    
    # Validate text safety (basic checks)
    try:
        validate_text_safety(request.text)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    try:
        # Call Go detection engine
        config = request.config or {}
        
        result = await client.detect(
            text=request.text,
            confidence_threshold=config.confidence_threshold or 0.6,
            detailed_response=config.include_reasoning if config.include_reasoning is not None else True
        )
        
        # Add request tracking
        total_time_ms = int((time.time() - request_start) * 1000)
        
        response = DetectionResponseModel(
            is_malicious=result.is_malicious,
            confidence=result.confidence,
            threat_types=result.threat_types,
            processing_time_ms=total_time_ms,  # Total gateway time
            reason=result.reason,
            endpoint=result.endpoint,
            request_id=request_id
        )
        
        logger.info(
            "Detection completed",
            request_id=request_id,
            is_malicious=result.is_malicious,
            confidence=result.confidence,
            threat_types=result.threat_types,
            total_time_ms=total_time_ms,
            go_processing_time_ms=result.processing_time_ms
        )
        
        # Log usage to database for analytics
        try:
            usage_log = UsageLog(
                api_key_id=uuid.UUID(api_key_info.key_id),
                endpoint="detect",
                request_size=len(request.text),
                response_time_ms=total_time_ms,
                is_malicious=result.is_malicious,
                confidence=result.confidence,
                threat_types=result.threat_types,
                user_agent=http_request.headers.get("user-agent"),
                ip_address=http_request.client.host if http_request.client else None,
                status_code=200
            )
            
            db.add(usage_log)
            await db.commit()
            
            logger.debug(
                "Usage logged successfully",
                request_id=request_id,
                key_id=api_key_info.key_id
            )
            
        except Exception as log_error:
            # Don't break the response if usage logging fails
            logger.error(
                "Failed to log usage",
                request_id=request_id,
                error=str(log_error),
                key_id=api_key_info.key_id
            )
            # Continue with the response - usage logging failure shouldn't affect detection
        
        return response
        
    except Exception as e:
        logger.error(
            "Detection failed",
            request_id=request_id,
            error=str(e),
            error_type=type(e).__name__
        )
        
        # Try fallback detection
        try:
            fallback_result = await client.detect_with_fallback(
                text=request.text,
                confidence_threshold=config.confidence_threshold or 0.6
            )
            
            total_time_ms = int((time.time() - request_start) * 1000)
            
            response = DetectionResponseModel(
                is_malicious=fallback_result.is_malicious,
                confidence=fallback_result.confidence,
                threat_types=fallback_result.threat_types,
                processing_time_ms=total_time_ms,
                reason=f"Fallback detection used: {fallback_result.reason}",
                endpoint="fallback",
                request_id=request_id
            )
            
            logger.warning("Used fallback detection", request_id=request_id)
            
            # Log usage for fallback detection too
            try:
                usage_log = UsageLog(
                    api_key_id=uuid.UUID(api_key_info.key_id),
                    endpoint="detect",
                    request_size=len(request.text),
                    response_time_ms=total_time_ms,
                    is_malicious=fallback_result.is_malicious,
                    confidence=fallback_result.confidence,
                    threat_types=fallback_result.threat_types,
                    user_agent=http_request.headers.get("user-agent"),
                    ip_address=http_request.client.host if http_request.client else None,
                    status_code=200
                )
                
                db.add(usage_log)
                await db.commit()
                
                logger.debug(
                    "Fallback usage logged successfully",
                    request_id=request_id,
                    key_id=api_key_info.key_id
                )
                
            except Exception as log_error:
                logger.error(
                    "Failed to log fallback usage",
                    request_id=request_id,
                    error=str(log_error),
                    key_id=api_key_info.key_id
                )
            
            return response
            
        except Exception as fallback_error:
            logger.error(
                "Fallback detection also failed",
                request_id=request_id,
                error=str(fallback_error)
            )
            
            # Log usage for failed request
            try:
                usage_log = UsageLog(
                    api_key_id=uuid.UUID(api_key_info.key_id),
                    endpoint="detect",
                    request_size=len(request.text),
                    response_time_ms=int((time.time() - request_start) * 1000),
                    is_malicious=None,  # Unknown due to failure
                    confidence=None,
                    threat_types=None,
                    user_agent=http_request.headers.get("user-agent"),
                    ip_address=http_request.client.host if http_request.client else None,
                    status_code=503
                )
                
                db.add(usage_log)
                await db.commit()
                
                logger.debug(
                    "Failed request usage logged",
                    request_id=request_id,
                    key_id=api_key_info.key_id
                )
                
            except Exception as log_error:
                logger.error(
                    "Failed to log failed request usage",
                    request_id=request_id,
                    error=str(log_error),
                    key_id=api_key_info.key_id
                )
            
            raise HTTPException(
                status_code=503,
                detail="Detection service unavailable - both primary and fallback failed"
            )


@router.post("/detect/batch", response_model=BatchDetectionResponse)
async def detect_batch(
    request: BatchDetectionRequest,
    client: DetectionClient = Depends(get_detection_client)
) -> BatchDetectionResponse:
    """
    Analyze multiple texts for prompt injection attacks
    
    **Batch processing endpoint** - processes up to 100 texts in a single request
    for efficient bulk analysis.
    
    **Features:**
    - Processes up to 100 texts per request
    - Maintains order of input requests
    - Individual error handling per text
    - Aggregated statistics and timing
    """
    batch_start = time.time()
    batch_id = str(uuid.uuid4())
    
    logger.info(
        "Processing batch detection",
        batch_id=batch_id,
        batch_size=len(request.requests),
        confidence_threshold=request.config.confidence_threshold if request.config else 0.6
    )
    
    results = []
    errors = []
    successful_count = 0
    failed_count = 0
    
    # Process each request in the batch
    for i, item in enumerate(request.requests):
        item_id = item.get('id', f'item_{i}')
        text = item['text']
        
        try:
            # Validate text safety
            validate_text_safety(text)
            
            # Get item-specific config or use batch default
            item_config = item.get('config', {})
            config = request.config or {}
            
            confidence_threshold = item_config.get(
                'confidence_threshold', 
                config.confidence_threshold or 0.6
            )
            
            # Call detection
            result = await client.detect(
                text=text,
                confidence_threshold=confidence_threshold,
                detailed_response=config.include_reasoning if config.include_reasoning is not None else False
            )
            
            response = DetectionResponseModel(
                is_malicious=result.is_malicious,
                confidence=result.confidence,
                threat_types=result.threat_types,
                processing_time_ms=result.processing_time_ms,
                reason=result.reason,
                endpoint=result.endpoint,
                request_id=item_id
            )
            
            results.append(response)
            errors.append(None)
            successful_count += 1
            
        except Exception as e:
            logger.warning(
                "Batch item failed",
                batch_id=batch_id,
                item_id=item_id,
                error=str(e)
            )
            
            results.append(None)
            errors.append(str(e))
            failed_count += 1
    
    total_time_ms = int((time.time() - batch_start) * 1000)
    
    logger.info(
        "Batch detection completed",
        batch_id=batch_id,
        successful_count=successful_count,
        failed_count=failed_count,
        total_time_ms=total_time_ms
    )
    
    return BatchDetectionResponse(
        results=results,
        errors=errors,
        total_processing_time_ms=total_time_ms,
        successful_count=successful_count,
        failed_count=failed_count
    )


@router.post("/detect/async", response_model=AsyncDetectionResponse)
async def detect_async(
    request: AsyncDetectionRequest,
    background_tasks: BackgroundTasks,
    client: DetectionClient = Depends(get_detection_client)
) -> AsyncDetectionResponse:
    """
    Queue text for async prompt injection detection
    
    **Asynchronous detection** - queues text for analysis and delivers
    results via webhook when complete.
    
    **Use Cases:**
    - Large text analysis
    - Non-blocking integrations
    - Bulk processing workflows
    """
    request_id = str(uuid.uuid4())
    
    logger.info(
        "Queuing async detection",
        request_id=request_id,
        webhook_url=str(request.webhook_url),
        text_length=len(request.text)
    )
    
    # Validate text safety
    try:
        validate_text_safety(request.text)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Queue background task for detection
    background_tasks.add_task(
        process_async_detection,
        request_id=request_id,
        text=request.text,
        webhook_url=str(request.webhook_url),
        config=request.config,
        metadata=request.metadata,
        client=client
    )
    
    return AsyncDetectionResponse(
        request_id=request_id,
        status="queued",
        estimated_completion_seconds=30,
        webhook_url=request.webhook_url
    )


async def process_async_detection(
    request_id: str,
    text: str,
    webhook_url: str,
    config: Any,
    metadata: Dict[str, Any],
    client: DetectionClient
):
    """Background task to process async detection and deliver webhook"""
    try:
        logger.info("Processing async detection", request_id=request_id)
        
        # Perform detection
        result = await client.detect(
            text=text,
            confidence_threshold=config.confidence_threshold if config else 0.6,
            detailed_response=config.include_reasoning if config and config.include_reasoning is not None else True
        )
        
        # Prepare webhook payload
        payload = {
            "request_id": request_id,
            "result": {
                "is_malicious": result.is_malicious,
                "confidence": result.confidence,
                "threat_types": result.threat_types,
                "processing_time_ms": result.processing_time_ms,
                "reason": result.reason,
                "endpoint": result.endpoint,
                "request_id": request_id
            },
            "metadata": metadata,
            "timestamp": time.time(),
            "status": "completed"
        }
        
        # TODO: Implement webhook delivery service
        # For now, just log the result
        logger.info(
            "Async detection completed",
            request_id=request_id,
            webhook_url=webhook_url,
            is_malicious=result.is_malicious
        )
        
    except Exception as e:
        logger.error(
            "Async detection failed",
            request_id=request_id,
            error=str(e)
        )
        
        # TODO: Send error webhook
        error_payload = {
            "request_id": request_id,
            "error": str(e),
            "metadata": metadata,
            "timestamp": time.time(),
            "status": "failed"
        }


@router.get("/health")
async def detection_health(
    client: DetectionClient = Depends(get_detection_client)
) -> Dict[str, Any]:
    """
    Health check for detection services
    
    Returns health status of both the API gateway and 
    the underlying Go detection engine.
    """
    try:
        # Check Go service health
        go_health = await client.health_check()
        
        return {
            "status": "healthy",
            "gateway_version": settings.VERSION,
            "detection_engine": go_health,
            "timestamp": time.time()
        }
        
    except Exception as e:
        logger.error("Detection health check failed", error=str(e))
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "gateway_version": settings.VERSION,
                "error": str(e),
                "timestamp": time.time()
            }
        )


@router.get("/metrics")
async def detection_metrics(
    client: DetectionClient = Depends(get_detection_client)
) -> Dict[str, Any]:
    """
    Get detection system metrics
    
    Returns performance metrics, usage statistics,
    and health indicators for monitoring.
    """
    try:
        # Get Go service metrics
        go_metrics = await client.get_metrics()
        
        return {
            "gateway_version": settings.VERSION,
            "detection_engine_metrics": go_metrics,
            "timestamp": time.time()
        }
        
    except Exception as e:
        logger.error("Failed to get detection metrics", error=str(e))
        return {
            "error": str(e),
            "timestamp": time.time()
        }


@router.get("/diagnose")
async def detection_diagnostics(
    client: DetectionClient = Depends(get_detection_client)
) -> Dict[str, Any]:
    """
    Get detailed diagnostic information
    
    Returns detailed information about detection models,
    endpoints, and system configuration for debugging.
    """
    try:
        # Get Go service diagnostics
        go_diagnostics = await client.diagnose_llm()
        
        return {
            "gateway_version": settings.VERSION,
            "detection_engine_url": settings.DETECTION_ENGINE_URL,
            "diagnostics": go_diagnostics,
            "timestamp": time.time()
        }
        
    except Exception as e:
        logger.error("Failed to get diagnostics", error=str(e))
        return {
            "error": str(e),
            "timestamp": time.time()
        }