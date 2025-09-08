#!/usr/bin/env python3
"""
Framework Integration Examples for Prompt Shield SDK

This example demonstrates how to integrate Prompt Shield with popular
Python web frameworks and AI libraries.
"""

import os
import sys
from typing import Dict, Any, Optional
import asyncio

# Add src to path for local development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from prompt_shield import PromptShieldClient, PromptShieldError


# =============================================================================
# FastAPI Integration
# =============================================================================

def fastapi_example():
    """FastAPI integration example"""
    print("🚀 FastAPI Integration Example")
    print("-" * 40)
    
    try:
        from fastapi import FastAPI, HTTPException, Depends, Request
        from fastapi.responses import JSONResponse
        from pydantic import BaseModel
        
        # Initialize Prompt Shield
        api_key = os.getenv('PROMPT_SHIELD_API_KEY', 'demo-key')
        shield_client = PromptShieldClient(api_key=api_key, base_url="http://localhost:8000")
        
        app = FastAPI(title="Chat API with Prompt Shield")
        
        # Request/Response models
        class ChatRequest(BaseModel):
            message: str
            user_id: Optional[str] = "anonymous"
        
        class ChatResponse(BaseModel):
            response: str
            blocked: bool
            reason: Optional[str] = None
            confidence: Optional[float] = None
        
        # Dependency for Prompt Shield client
        def get_shield_client():
            return shield_client
        
        # Middleware for automatic protection (optional)
        @app.middleware("http")
        async def prompt_shield_middleware(request: Request, call_next):
            """Automatically protect all POST requests with text content"""
            
            # Only check specific endpoints
            if request.method == "POST" and request.url.path in ["/chat", "/analyze"]:
                try:
                    # Get request body
                    body = await request.body()
                    if body:
                        # Simple check for JSON with 'message' field
                        import json
                        try:
                            data = json.loads(body)
                            if isinstance(data, dict) and "message" in data:
                                message = data["message"]
                                
                                # Check with Prompt Shield
                                result = await shield_client.detect_async(message)
                                
                                if result.is_malicious:
                                    return JSONResponse(
                                        status_code=400,
                                        content={
                                            "error": "Malicious content detected",
                                            "reason": result.reason,
                                            "threat_types": result.threat_types,
                                            "confidence": result.confidence
                                        }
                                    )
                        except json.JSONDecodeError:
                            pass  # Not JSON, skip check
                            
                except Exception as e:
                    print(f"Middleware error: {e}")
                    # Don't block request on middleware errors
                    pass
            
            response = await call_next(request)
            return response
        
        @app.post("/chat", response_model=ChatResponse)
        async def chat_endpoint(
            request: ChatRequest,
            shield: PromptShieldClient = Depends(get_shield_client)
        ):
            """Chat endpoint with Prompt Shield protection"""
            
            try:
                # Check input for prompt injection
                detection = await shield.detect_async(request.message)
                
                if detection.is_malicious:
                    return ChatResponse(
                        response="I can't process that request due to security concerns.",
                        blocked=True,
                        reason=detection.reason,
                        confidence=detection.confidence
                    )
                
                # Simulate AI response generation
                ai_response = f"Thank you for your message: '{request.message[:50]}...'. This is a safe response."
                
                # Optionally check AI response too
                output_check = await shield.detect_async(ai_response)
                if output_check.is_malicious:
                    ai_response = "I apologize, I'm having trouble generating a safe response."
                
                return ChatResponse(
                    response=ai_response,
                    blocked=False,
                    confidence=detection.confidence
                )
                
            except PromptShieldError as e:
                raise HTTPException(status_code=500, detail=f"Security check failed: {str(e)}")
        
        @app.get("/health")
        async def health_check():
            """Health check endpoint"""
            return {"status": "healthy", "prompt_shield": "active"}
        
        print("✅ FastAPI app configured with Prompt Shield")
        print("   Endpoints: POST /chat, GET /health")
        print("   Features: Automatic middleware protection, dependency injection")
        
        return app
        
    except ImportError:
        print("❌ FastAPI not installed. Install with: pip install fastapi uvicorn")
        return None


# =============================================================================
# Flask Integration  
# =============================================================================

def flask_example():
    """Flask integration example"""
    print("\n🌶️  Flask Integration Example")
    print("-" * 40)
    
    try:
        from flask import Flask, request, jsonify
        from functools import wraps
        
        # Initialize Flask app
        app = Flask(__name__)
        
        # Initialize Prompt Shield
        api_key = os.getenv('PROMPT_SHIELD_API_KEY', 'demo-key')
        shield_client = PromptShieldClient(api_key=api_key, base_url="http://localhost:8000")
        
        # Decorator for prompt protection
        def protect_prompt(field_name='message'):
            """Decorator to protect specific fields in request JSON"""
            def decorator(f):
                @wraps(f)
                def wrapper(*args, **kwargs):
                    try:
                        data = request.get_json()
                        if not data or field_name not in data:
                            return jsonify({"error": f"Missing required field: {field_name}"}), 400
                        
                        text_to_check = data[field_name]
                        
                        # Synchronous detection (Flask is typically sync)
                        result = shield_client.detect(text_to_check)
                        
                        if result.is_malicious:
                            return jsonify({
                                "error": "Content blocked by security filter",
                                "reason": result.reason,
                                "threat_types": result.threat_types,
                                "confidence": result.confidence
                            }), 400
                        
                        # Add detection result to request context
                        request.shield_result = result
                        
                        return f(*args, **kwargs)
                        
                    except PromptShieldError as e:
                        return jsonify({"error": f"Security check failed: {str(e)}"}), 500
                
                return wrapper
            return decorator
        
        @app.route('/chat', methods=['POST'])
        @protect_prompt('message')
        def chat():
            """Chat endpoint with protection"""
            data = request.get_json()
            user_message = data['message']
            
            # Generate response (simulate AI)
            ai_response = f"I received your message: '{user_message[:30]}...'. How can I help you further?"
            
            return jsonify({
                "response": ai_response,
                "security": {
                    "blocked": False,
                    "confidence": request.shield_result.confidence,
                    "processing_time_ms": request.shield_result.processing_time_ms
                }
            })
        
        @app.route('/analyze', methods=['POST'])
        def analyze():
            """Analysis endpoint with manual protection"""
            data = request.get_json()
            
            if not data or 'text' not in data:
                return jsonify({"error": "Missing 'text' field"}), 400
            
            try:
                result = shield_client.detect(data['text'])
                
                return jsonify({
                    "text": data['text'][:100] + "..." if len(data['text']) > 100 else data['text'],
                    "analysis": {
                        "is_malicious": result.is_malicious,
                        "confidence": result.confidence,
                        "threat_types": result.threat_types,
                        "reason": result.reason,
                        "processing_time_ms": result.processing_time_ms
                    }
                })
                
            except PromptShieldError as e:
                return jsonify({"error": str(e)}), 500
        
        @app.route('/health')
        def health():
            """Health check"""
            return jsonify({"status": "healthy", "prompt_shield": "active"})
        
        print("✅ Flask app configured with Prompt Shield")
        print("   Endpoints: POST /chat, POST /analyze, GET /health")
        print("   Features: Decorator-based protection, manual checks")
        
        return app
        
    except ImportError:
        print("❌ Flask not installed. Install with: pip install flask")
        return None


# =============================================================================
# Django Integration (Middleware)
# =============================================================================

def django_middleware_example():
    """Django middleware integration example"""
    print("\n🎸 Django Middleware Example")
    print("-" * 40)
    
    django_middleware_code = '''
# Add to your Django project: middleware/prompt_shield.py

from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
import json
import asyncio
from prompt_shield import PromptShieldClient, PromptShieldError

class PromptShieldMiddleware(MiddlewareMixin):
    """Django middleware for Prompt Shield integration"""
    
    def __init__(self, get_response):
        super().__init__(get_response)
        
        # Initialize Prompt Shield client
        api_key = getattr(settings, 'PROMPT_SHIELD_API_KEY', None)
        base_url = getattr(settings, 'PROMPT_SHIELD_URL', 'http://localhost:8000')
        
        if not api_key:
            raise ValueError("PROMPT_SHIELD_API_KEY must be set in Django settings")
        
        self.shield_client = PromptShieldClient(
            api_key=api_key,
            base_url=base_url
        )
        
        # Configure which paths to protect
        self.protected_paths = getattr(settings, 'PROMPT_SHIELD_PROTECTED_PATHS', [
            '/api/chat/',
            '/api/analyze/',
        ])
        
        # Configure which fields to check
        self.protected_fields = getattr(settings, 'PROMPT_SHIELD_PROTECTED_FIELDS', [
            'message', 'text', 'prompt', 'query'
        ])
    
    def process_request(self, request):
        """Check requests for prompt injection"""
        
        # Only check POST requests to protected paths
        if request.method != 'POST':
            return None
            
        if not any(request.path.startswith(path) for path in self.protected_paths):
            return None
        
        try:
            # Parse request body
            if hasattr(request, '_body'):
                body = request._body
            else:
                body = request.body
            
            if not body:
                return None
            
            # Try to parse JSON
            try:
                data = json.loads(body.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None
            
            # Check protected fields
            for field in self.protected_fields:
                if field in data and isinstance(data[field], str):
                    text_to_check = data[field]
                    
                    # Synchronous detection
                    result = self.shield_client.detect(text_to_check)
                    
                    if result.is_malicious:
                        return JsonResponse({
                            'error': 'Content blocked by security filter',
                            'field': field,
                            'reason': result.reason,
                            'threat_types': result.threat_types,
                            'confidence': result.confidence
                        }, status=400)
                    
                    # Add result to request for later use
                    if not hasattr(request, 'shield_results'):
                        request.shield_results = {}
                    request.shield_results[field] = result
        
        except PromptShieldError as e:
            return JsonResponse({
                'error': 'Security check failed',
                'details': str(e)
            }, status=500)
        except Exception as e:
            # Log error but don't block request
            print(f"PromptShieldMiddleware error: {e}")
            return None
        
        return None

# Django settings.py additions:
PROMPT_SHIELD_API_KEY = 'your-api-key-here'
PROMPT_SHIELD_URL = 'http://localhost:8000'
PROMPT_SHIELD_PROTECTED_PATHS = ['/api/chat/', '/api/analyze/']
PROMPT_SHIELD_PROTECTED_FIELDS = ['message', 'text', 'prompt']

MIDDLEWARE = [
    # ... other middleware
    'myapp.middleware.prompt_shield.PromptShieldMiddleware',
    # ... more middleware
]

# Django views.py example:
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import json

@csrf_exempt
@require_http_methods(["POST"])
def chat_view(request):
    data = json.loads(request.body)
    message = data['message']
    
    # Shield results available from middleware
    if hasattr(request, 'shield_results') and 'message' in request.shield_results:
        shield_result = request.shield_results['message']
        print(f"Message safety check: {shield_result.confidence:.1%} confidence")
    
    # Generate AI response
    response = f"Thank you for your message: {message}"
    
    return JsonResponse({
        'response': response,
        'status': 'success'
    })
'''
    
    print("📝 Django middleware implementation:")
    print("   - Automatic protection for configured paths and fields")  
    print("   - Configurable via Django settings")
    print("   - Results available in request object")
    print("   - See code above for full implementation")
    
    return django_middleware_code


# =============================================================================
# LangChain Integration
# =============================================================================

async def langchain_example():
    """LangChain integration example (conceptual)"""
    print("\n🦜 LangChain Integration Example (Conceptual)")
    print("-" * 40)
    
    langchain_code = '''
# Custom LangChain component with Prompt Shield
from langchain.schema import BaseOutputParser
from langchain.callbacks.base import BaseCallbackHandler
from prompt_shield import PromptShieldClient

class PromptShieldInputValidator:
    """LangChain input validator using Prompt Shield"""
    
    def __init__(self, api_key: str, base_url: str = "http://localhost:8000"):
        self.shield_client = PromptShieldClient(api_key=api_key, base_url=base_url)
    
    async def validate_input(self, input_text: str) -> dict:
        """Validate input before sending to LLM"""
        result = await self.shield_client.detect_async(input_text)
        
        return {
            "is_safe": not result.is_malicious,
            "confidence": result.confidence,
            "threat_types": result.threat_types,
            "reason": result.reason
        }

class PromptShieldCallback(BaseCallbackHandler):
    """LangChain callback for Prompt Shield integration"""
    
    def __init__(self, shield_client: PromptShieldClient):
        self.shield_client = shield_client
    
    def on_llm_start(self, serialized, prompts, **kwargs):
        """Check prompts before sending to LLM"""
        for i, prompt in enumerate(prompts):
            try:
                result = self.shield_client.detect(prompt)
                if result.is_malicious:
                    print(f"⚠️ Prompt {i} flagged: {result.reason}")
            except Exception as e:
                print(f"Shield check failed: {e}")
    
    def on_llm_end(self, response, **kwargs):
        """Check LLM outputs for safety"""
        if hasattr(response, 'generations'):
            for generation in response.generations:
                for gen in generation:
                    if hasattr(gen, 'text'):
                        try:
                            result = self.shield_client.detect(gen.text)
                            if result.is_malicious:
                                print(f"⚠️ Output flagged: {result.reason}")
                        except Exception as e:
                            print(f"Output check failed: {e}")

# Usage example:
from langchain.llms import OpenAI
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate

# Initialize Prompt Shield
shield_client = PromptShieldClient(api_key="your-key")
shield_callback = PromptShieldCallback(shield_client)

# Create LangChain components
llm = OpenAI(callbacks=[shield_callback])
prompt = PromptTemplate(template="Answer this question: {question}")
chain = LLMChain(llm=llm, prompt=prompt)

# The callback will automatically check inputs and outputs
response = chain.run(question="What is the capital of France?")
'''
    
    print("📝 LangChain integration concepts:")
    print("   - Input validation before LLM calls")
    print("   - Output validation after LLM responses")  
    print("   - Custom callbacks for automatic protection")
    print("   - See code above for implementation details")
    
    return langchain_code


# =============================================================================
# Main Demo Function
# =============================================================================

async def main():
    """Run framework integration examples"""
    print("🛡️  Prompt Shield Framework Integration Examples")
    print("=" * 60)
    
    # Check API key
    api_key = os.getenv('PROMPT_SHIELD_API_KEY')
    if not api_key:
        print("⚠️  Set PROMPT_SHIELD_API_KEY for full functionality")
        print("   export PROMPT_SHIELD_API_KEY='your-api-key'")
        print("Continuing with demo examples...\n")
    
    try:
        # FastAPI example
        fastapi_app = fastapi_example()
        
        # Flask example
        flask_app = flask_example()
        
        # Django example
        django_code = django_middleware_example()
        
        # LangChain example
        langchain_code = await langchain_example()
        
        print("\n🎯 Integration Summary:")
        print("=" * 40)
        print("✅ FastAPI: Middleware + dependency injection")
        print("✅ Flask: Decorators + manual checks")
        print("✅ Django: Middleware with settings configuration")
        print("✅ LangChain: Callbacks for input/output validation")
        
        print("\n📚 Next Steps:")
        print("1. Choose the framework that matches your stack")
        print("2. Copy the relevant integration code")  
        print("3. Install required dependencies (fastapi, flask, etc.)")
        print("4. Configure your API key and endpoint URL")
        print("5. Test with both safe and malicious inputs")
        
        print("\n💡 Pro Tips:")
        print("- Always validate both inputs AND outputs")
        print("- Use caching to reduce API calls for repeated content")
        print("- Implement graceful fallbacks for API errors")
        print("- Monitor false positives and adjust confidence thresholds")
        print("- Consider async operations for better performance")
        
    except Exception as e:
        print(f"💥 Demo failed: {e}")
        raise


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demo interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        raise