"""
HTTP client for communicating with the Go detection engine

Handles request/response translation between FastAPI and Go service
with proper error handling, timeouts, and fallback mechanisms.
"""
import time
from typing import Dict, Any, Optional
import httpx
import structlog
from pydantic import BaseModel

logger = structlog.get_logger()


class DetectionRequest(BaseModel):
    """Request model matching Go service expectations"""
    text: str
    config: Optional[Dict[str, Any]] = None


class DetectionResponse(BaseModel):
    """Response model matching Go service format"""
    is_malicious: bool
    confidence: float
    threat_types: list[str]
    processing_time_ms: int
    reason: Optional[str] = None
    endpoint: Optional[str] = None


class DetectionClient:
    """HTTP client for the Go detection engine"""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(30.0, connect=5.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=5),
            headers={"User-Agent": "PromptDefense-Gateway/1.0"}
        )
        self.logger = logger.bind(service="detection_client")
    
    async def detect(
        self,
        text: str,
        confidence_threshold: float = 0.6,
        detailed_response: bool = True
    ) -> DetectionResponse:
        """
        Analyze text for prompt injection attacks
        
        Args:
            text: Text to analyze
            confidence_threshold: Minimum confidence for positive detection
            detailed_response: Include detailed reasoning in response
            
        Returns:
            DetectionResponse with analysis results
            
        Raises:
            httpx.HTTPStatusError: On HTTP errors from Go service
            httpx.TimeoutException: On request timeout
            httpx.ConnectError: On connection failure
        """
        start_time = time.time()
        
        request_data = DetectionRequest(
            text=text,
            config={
                "confidence_threshold": confidence_threshold,
                "detailed_response": detailed_response
            }
        )
        
        self.logger.info(
            "Sending detection request",
            text_length=len(text),
            confidence_threshold=confidence_threshold
        )
        
        try:
            response = await self.client.post(
                "/v1/detect",
                json=request_data.model_dump(exclude_none=True)
            )
            response.raise_for_status()
            
            response_data = response.json()
            detection_response = DetectionResponse(**response_data)
            
            request_time = (time.time() - start_time) * 1000  # ms
            
            self.logger.info(
                "Detection completed",
                is_malicious=detection_response.is_malicious,
                confidence=detection_response.confidence,
                threat_types=detection_response.threat_types,
                request_time_ms=request_time,
                go_processing_time_ms=detection_response.processing_time_ms
            )
            
            return detection_response
            
        except httpx.HTTPStatusError as e:
            self.logger.error(
                "HTTP error from detection engine",
                status_code=e.response.status_code,
                response_text=e.response.text
            )
            raise
            
        except httpx.TimeoutException:
            self.logger.error("Detection request timed out")
            raise
            
        except httpx.ConnectError as e:
            self.logger.error("Failed to connect to detection engine", error=str(e))
            raise
            
        except Exception as e:
            self.logger.error("Unexpected error in detection request", error=str(e))
            raise
    
    async def detect_with_fallback(
        self,
        text: str,
        confidence_threshold: float = 0.6
    ) -> DetectionResponse:
        """
        Detect with fallback to basic heuristics on service failure
        
        Args:
            text: Text to analyze
            confidence_threshold: Minimum confidence for positive detection
            
        Returns:
            DetectionResponse (may be from fallback logic)
        """
        try:
            return await self.detect(text, confidence_threshold)
        
        except (httpx.ConnectError, httpx.TimeoutException):
            self.logger.warning("Detection engine unavailable, using fallback")
            return self._fallback_detection(text)
        
        except httpx.HTTPStatusError as e:
            if e.response.status_code >= 500:
                self.logger.warning("Detection engine error, using fallback")
                return self._fallback_detection(text)
            raise
    
    def _fallback_detection(self, text: str) -> DetectionResponse:
        """
        Simple heuristic-based detection for when Go service is unavailable
        
        This is a basic fallback - not as accurate as the ML models
        but provides some protection during service outages.
        """
        # Basic heuristic patterns for prompt injection
        injection_patterns = [
            "ignore previous instructions",
            "forget everything",
            "disregard",
            "system prompt",
            "you are now",
            "pretend to be",
            "act as",
            "jailbreak",
            "bypass safety",
            "roleplay as",
        ]
        
        text_lower = text.lower()
        detected_patterns = [
            pattern for pattern in injection_patterns 
            if pattern in text_lower
        ]
        
        # Simple scoring based on pattern matches
        is_malicious = len(detected_patterns) > 0
        confidence = min(0.8, len(detected_patterns) * 0.3) if is_malicious else 0.1
        
        threat_types = ["jailbreak"] if is_malicious else []
        
        return DetectionResponse(
            is_malicious=is_malicious,
            confidence=confidence,
            threat_types=threat_types,
            processing_time_ms=1,  # Fallback is instant
            reason=f"Fallback detection - matched patterns: {detected_patterns}" if detected_patterns else "Fallback detection - no patterns matched",
            endpoint="fallback"
        )
    
    async def health_check(self) -> Dict[str, Any]:
        """Check health of the Go detection engine"""
        try:
            response = await self.client.get("/health", timeout=5.0)
            response.raise_for_status()
            return response.json()
        
        except Exception as e:
            self.logger.error("Health check failed", error=str(e))
            return {
                "status": "unhealthy",
                "error": str(e)
            }
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get metrics from the Go detection engine"""
        try:
            response = await self.client.get("/v1/metrics", timeout=5.0)
            response.raise_for_status()
            return response.json()
        
        except Exception as e:
            self.logger.error("Failed to get metrics", error=str(e))
            return {
                "error": str(e)
            }
    
    async def diagnose_llm(self) -> Dict[str, Any]:
        """Get LLM diagnostic information"""
        try:
            response = await self.client.get("/v1/diagnose-llm", timeout=5.0)
            response.raise_for_status()
            return response.json()
        
        except Exception as e:
            self.logger.error("Failed to get LLM diagnostics", error=str(e))
            return {
                "error": str(e)
            }
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
        self.logger.info("Detection client closed")