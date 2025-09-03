"""
Webhook management API endpoints

Handles webhook registration, testing, and delivery management
for async detection result notifications.
"""
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

import structlog
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field, HttpUrl, validator

logger = structlog.get_logger()
router = APIRouter()


class WebhookRegisterRequest(BaseModel):
    """Request to register a new webhook endpoint"""
    url: HttpUrl = Field(..., description="Webhook endpoint URL")
    events: List[str] = Field(
        default=["detection_complete"],
        description="Events to subscribe to"
    )
    secret_token: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Secret token for webhook verification"
    )
    description: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Human-readable description"
    )
    
    @validator('events')
    def validate_events(cls, v):
        """Validate webhook event types"""
        valid_events = [
            "detection_complete",
            "batch_complete",
            "detection_failed",
            "rate_limit_exceeded"
        ]
        
        for event in v:
            if event not in valid_events:
                raise ValueError(f'Invalid event type: {event}. Valid types: {valid_events}')
        
        return v


class WebhookResponse(BaseModel):
    """Response for webhook registration"""
    webhook_id: str = Field(..., description="Unique webhook identifier")
    url: HttpUrl = Field(..., description="Webhook endpoint URL")
    events: List[str] = Field(..., description="Subscribed events")
    secret_token: Optional[str] = Field(None, description="Secret token (masked)")
    description: Optional[str] = Field(None, description="Description")
    is_active: bool = Field(..., description="Whether webhook is active")
    created_at: datetime = Field(..., description="Creation timestamp")
    last_triggered_at: Optional[datetime] = Field(None, description="Last trigger time")


class WebhookTestRequest(BaseModel):
    """Request to test webhook delivery"""
    webhook_id: Optional[str] = Field(None, description="Specific webhook to test")
    test_payload: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Custom test payload (uses default if not provided)"
    )


class WebhookTestResponse(BaseModel):
    """Response for webhook test"""
    webhook_id: str = Field(..., description="Tested webhook ID")
    success: bool = Field(..., description="Whether test was successful")
    http_status: Optional[int] = Field(None, description="HTTP response status")
    response_time_ms: int = Field(..., description="Response time in milliseconds")
    error: Optional[str] = Field(None, description="Error message if failed")
    tested_at: datetime = Field(..., description="Test timestamp")


class WebhookDeliveryLog(BaseModel):
    """Webhook delivery log entry"""
    delivery_id: str = Field(..., description="Unique delivery ID")
    webhook_id: str = Field(..., description="Webhook ID")
    event_type: str = Field(..., description="Event that triggered the webhook")
    http_status: Optional[int] = Field(None, description="HTTP response status")
    response_time_ms: Optional[int] = Field(None, description="Response time")
    attempt_count: int = Field(..., description="Delivery attempt number")
    success: bool = Field(..., description="Whether delivery was successful")
    error: Optional[str] = Field(None, description="Error message if failed")
    delivered_at: datetime = Field(..., description="Delivery timestamp")
    next_retry_at: Optional[datetime] = Field(None, description="Next retry time if failed")


@router.post("/register", response_model=WebhookResponse)
async def register_webhook(
    request: WebhookRegisterRequest,
    # TODO: Add API key authentication
    # api_key_info = Depends(authenticate_api_key)
) -> WebhookResponse:
    """
    Register a new webhook endpoint
    
    **Webhook Registration** - Register an endpoint to receive detection results
    and other events. Supports secret token verification and event filtering.
    
    **Supported Events:**
    - `detection_complete`: Single detection finished
    - `batch_complete`: Batch detection finished  
    - `detection_failed`: Detection failed
    - `rate_limit_exceeded`: Rate limit hit
    
    **Payload Format:**
    ```json
    {
        "event": "detection_complete",
        "request_id": "uuid",
        "result": { ... },
        "timestamp": 1234567890,
        "api_key_id": "key_id"
    }
    ```
    """
    try:
        webhook_id = str(uuid.uuid4())
        
        # TODO: Store webhook in database
        # For now, return mock response
        
        logger.info(
            "Webhook registered",
            webhook_id=webhook_id,
            url=str(request.url),
            events=request.events,
            has_secret=bool(request.secret_token)
        )
        
        return WebhookResponse(
            webhook_id=webhook_id,
            url=request.url,
            events=request.events,
            secret_token="***hidden***" if request.secret_token else None,
            description=request.description,
            is_active=True,
            created_at=datetime.utcnow(),
            last_triggered_at=None
        )
        
    except Exception as e:
        logger.error("Failed to register webhook", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to register webhook")


@router.get("/list", response_model=List[WebhookResponse])
async def list_webhooks(
    # TODO: Add API key authentication
    # api_key_info = Depends(authenticate_api_key)
) -> List[WebhookResponse]:
    """
    List all registered webhooks for your API key
    
    **Webhook Management** - View all your registered webhook endpoints
    with their configuration and status.
    """
    try:
        # TODO: Get webhooks from database
        # For now, return mock data
        
        mock_webhooks = [
            WebhookResponse(
                webhook_id=str(uuid.uuid4()),
                url=HttpUrl("https://api.example.com/webhooks/detection"),
                events=["detection_complete", "batch_complete"],
                secret_token="***hidden***",
                description="Production detection webhook",
                is_active=True,
                created_at=datetime.utcnow(),
                last_triggered_at=datetime.utcnow()
            )
        ]
        
        logger.info("Webhooks listed", count=len(mock_webhooks))
        return mock_webhooks
        
    except Exception as e:
        logger.error("Failed to list webhooks", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to list webhooks")


@router.post("/test", response_model=WebhookTestResponse)
async def test_webhook(
    request: WebhookTestRequest,
    background_tasks: BackgroundTasks,
    # TODO: Add API key authentication
    # api_key_info = Depends(authenticate_api_key)
) -> WebhookTestResponse:
    """
    Test webhook delivery
    
    **Webhook Testing** - Send a test payload to your webhook endpoint
    to verify it's working correctly. Uses a sample detection result payload.
    """
    try:
        webhook_id = request.webhook_id or str(uuid.uuid4())
        
        # Default test payload if not provided
        test_payload = request.test_payload or {
            "event": "detection_complete",
            "request_id": "test_" + str(uuid.uuid4()),
            "result": {
                "is_malicious": True,
                "confidence": 0.85,
                "threat_types": ["jailbreak"],
                "processing_time_ms": 45,
                "reason": "Test webhook payload - detected jailbreak attempt",
                "endpoint": "test"
            },
            "timestamp": datetime.utcnow().timestamp(),
            "api_key_id": "test_key",
            "_test": True
        }
        
        # TODO: Actually send webhook test
        # For now, simulate success
        
        logger.info("Webhook test initiated", webhook_id=webhook_id)
        
        return WebhookTestResponse(
            webhook_id=webhook_id,
            success=True,
            http_status=200,
            response_time_ms=150,
            error=None,
            tested_at=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error("Failed to test webhook", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to test webhook")


@router.get("/{webhook_id}/deliveries", response_model=List[WebhookDeliveryLog])
async def get_webhook_deliveries(
    webhook_id: str,
    limit: int = 50,
    # TODO: Add API key authentication
    # api_key_info = Depends(authenticate_api_key)
) -> List[WebhookDeliveryLog]:
    """
    Get delivery history for a webhook
    
    **Delivery Logs** - View the delivery history for a specific webhook,
    including success/failure status, retry attempts, and timing information.
    """
    try:
        if limit > 100:
            raise HTTPException(status_code=400, detail="Limit cannot exceed 100")
        
        # TODO: Get actual delivery logs from database
        # For now, return mock data
        
        mock_deliveries = [
            WebhookDeliveryLog(
                delivery_id=str(uuid.uuid4()),
                webhook_id=webhook_id,
                event_type="detection_complete",
                http_status=200,
                response_time_ms=120,
                attempt_count=1,
                success=True,
                error=None,
                delivered_at=datetime.utcnow(),
                next_retry_at=None
            )
        ]
        
        logger.info("Webhook deliveries retrieved", webhook_id=webhook_id, count=len(mock_deliveries))
        return mock_deliveries
        
    except Exception as e:
        logger.error("Failed to get webhook deliveries", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to get webhook deliveries")


@router.put("/{webhook_id}/toggle")
async def toggle_webhook(
    webhook_id: str,
    active: bool = True,
    # TODO: Add API key authentication
    # api_key_info = Depends(authenticate_api_key)
) -> Dict[str, Any]:
    """
    Enable or disable a webhook
    
    **Webhook Control** - Temporarily disable or re-enable webhook delivery
    without deleting the webhook configuration.
    """
    try:
        # TODO: Update webhook status in database
        
        action = "enabled" if active else "disabled"
        logger.info("Webhook toggled", webhook_id=webhook_id, action=action)
        
        return {
            "webhook_id": webhook_id,
            "is_active": active,
            "action": action,
            "updated_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to toggle webhook", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to toggle webhook")


@router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    # TODO: Add API key authentication
    # api_key_info = Depends(authenticate_api_key)
) -> Dict[str, str]:
    """
    Delete a webhook permanently
    
    **Permanent Action** - Remove webhook configuration and stop all deliveries.
    This action cannot be undone.
    """
    try:
        # TODO: Delete webhook from database
        
        logger.info("Webhook deleted", webhook_id=webhook_id)
        
        return {
            "message": "Webhook deleted successfully",
            "webhook_id": webhook_id,
            "deleted_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to delete webhook", error=str(e))
        raise HTTPException(status_code=500, detail="Failed to delete webhook")