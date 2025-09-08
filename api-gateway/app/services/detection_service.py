"""
Detection Service - Interface to Detection Engine
Handles communication with the Go detection engine
"""

import httpx
import asyncio
from typing import Dict, Any, Optional
from app.core.config import get_settings

settings = get_settings()


class DetectionService:
    """Service to communicate with Go detection engine"""
    
    def __init__(self):
        self.detection_engine_url = getattr(settings, 'DETECTION_ENGINE_URL', 'http://localhost:8080')
        self.timeout = 30.0
        self.client = httpx.AsyncClient(timeout=self.timeout)
    
    async def detect_with_tenant_settings(
        self, 
        text: str, 
        tenant_settings: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform detection with tenant-specific settings
        
        Args:
            text: Text to analyze
            tenant_settings: Tenant-specific configuration
            
        Returns:
            Detection result dictionary
        """
        try:
            # Prepare request payload
            payload = {
                "text": text,
                "tenant_context": {
                    "tenant_id": tenant_settings.get('tenant_id'),
                    "detection_threshold": tenant_settings.get('detection_threshold', 0.7)
                }
            }
            
            # Call detection engine
            response = await self.client.post(
                f"{self.detection_engine_url}/v1/detect",
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "PromptShield-Gateway/2.0"
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                
                # Ensure consistent response format
                return {
                    "is_malicious": result.get("is_malicious", False),
                    "confidence": result.get("confidence", 0.0),
                    "threat_types": result.get("threat_types", []),
                    "reason": result.get("reason", "No specific reason provided"),
                    "model_used": result.get("endpoint", "unknown"),
                    "processing_time_engine_ms": result.get("processing_time_ms", 0),
                    "model_info": {
                        "endpoint": result.get("endpoint"),
                        "model_provider": self._extract_provider(result.get("endpoint", ""))
                    }
                }
            
            elif response.status_code == 503:
                # Service unavailable - all models down
                return self._fallback_response(
                    text, 
                    "Detection service temporarily unavailable", 
                    tenant_settings
                )
            
            else:
                # Other errors
                return self._fallback_response(
                    text,
                    f"Detection service error: HTTP {response.status_code}",
                    tenant_settings
                )
                
        except httpx.TimeoutException:
            return self._fallback_response(
                text,
                "Detection service timeout",
                tenant_settings
            )
        
        except httpx.ConnectError:
            return self._fallback_response(
                text,
                "Cannot connect to detection service",
                tenant_settings
            )
        
        except Exception as e:
            return self._fallback_response(
                text,
                f"Unexpected error: {str(e)}",
                tenant_settings
            )
    
    def _fallback_response(
        self, 
        text: str, 
        error_reason: str, 
        tenant_settings: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate fallback response when detection engine is unavailable
        
        For security, we implement fail-safe behavior:
        - Simple keyword-based detection as fallback
        - Conservative approach - block obviously malicious patterns
        """
        
        # Simple keyword-based fallback detection
        malicious_keywords = [
            "ignore all previous instructions",
            "ignore the above",
            "disregard previous",
            "system prompt",
            "jailbreak",
            "dan mode",
            "evil assistant",
            "forget everything",
            "override security",
            "bypass safety"
        ]
        
        text_lower = text.lower()
        detected_keywords = [kw for kw in malicious_keywords if kw in text_lower]
        
        is_malicious = len(detected_keywords) > 0
        confidence = min(0.8, len(detected_keywords) * 0.3) if is_malicious else 0.1
        
        threat_types = []
        if detected_keywords:
            if any(kw in ["ignore", "disregard", "forget"] for kw in " ".join(detected_keywords).split()):
                threat_types.append("instruction_override")
            if any(kw in ["system prompt", "jailbreak", "dan mode"] for kw in " ".join(detected_keywords).split()):
                threat_types.append("jailbreak")
        
        return {
            "is_malicious": is_malicious,
            "confidence": confidence,
            "threat_types": threat_types,
            "reason": f"Fallback detection: {error_reason}. Keyword-based analysis used.",
            "model_used": "fallback-keyword-detector",
            "processing_time_engine_ms": 0,
            "model_info": {
                "endpoint": "fallback",
                "model_provider": "internal"
            },
            "fallback_used": True,
            "fallback_reason": error_reason,
            "detected_keywords": detected_keywords
        }
    
    def _extract_provider(self, endpoint: str) -> str:
        """Extract model provider from endpoint name"""
        if not endpoint:
            return "unknown"
        
        endpoint_lower = endpoint.lower()
        
        if "gemini" in endpoint_lower:
            return "google"
        elif "gpt" in endpoint_lower or "openai" in endpoint_lower:
            return "openai"
        elif "claude" in endpoint_lower or "anthropic" in endpoint_lower:
            return "anthropic"
        elif "huggingface" in endpoint_lower or "deberta" in endpoint_lower:
            return "huggingface"
        elif "kimi" in endpoint_lower or "moonshot" in endpoint_lower:
            return "moonshot"
        elif "deepseek" in endpoint_lower:
            return "deepseek"
        else:
            return "unknown"
    
    async def health_check(self) -> Dict[str, Any]:
        """Check detection engine health"""
        try:
            response = await self.client.get(
                f"{self.detection_engine_url}/health",
                timeout=5.0
            )
            
            if response.status_code == 200:
                health_data = response.json()
                return {
                    "status": "healthy",
                    "detection_engine": health_data,
                    "response_time_ms": response.elapsed.total_seconds() * 1000
                }
            else:
                return {
                    "status": "unhealthy",
                    "error": f"HTTP {response.status_code}",
                    "detection_engine": None
                }
        
        except Exception as e:
            return {
                "status": "unavailable",
                "error": str(e),
                "detection_engine": None
            }
    
    async def get_model_status(self) -> Dict[str, Any]:
        """Get status of available models from health endpoint"""
        try:
            response = await self.client.get(
                f"{self.detection_engine_url}/health",
                timeout=10.0
            )
            
            if response.status_code == 200:
                health_data = response.json()
                return {
                    "available_models": health_data.get("models_available", 0),
                    "total_models": health_data.get("total_models", 0),
                    "circuit_breakers": health_data.get("circuit_breakers", {}),
                    "status": "healthy" if health_data.get("status") == "healthy" else "degraded"
                }
            else:
                return {
                    "available_models": 0,
                    "total_models": 0,
                    "error": f"HTTP {response.status_code}",
                    "status": "unreachable"
                }
        
        except Exception as e:
            return {
                "available_models": 0,
                "total_models": 0,
                "error": str(e),
                "status": "unreachable"
            }
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()