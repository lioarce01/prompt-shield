# Detection Engine (Go)

High-performance prompt injection detection with **circuit breaker fallback** and multi-model AI pipeline.

## Features

- **Circuit Breaker Fallback**: ProtectAI DeBERTa → Meta Llama → Gemini 2.0 Flash → HTTP 503
- **Zero Downtime**: Auto-recovery when models fail, no cascading failures
- **Flexible Model Registry**: Easy provider swapping (OpenAI, Claude, Grok ready)
- **Encoding preprocessing**: Base64, Hex, ROT13, ASCII detection
- **Sub-2s latency** with intelligent fallback
- **Multi-language support**: Chinese, Arabic, Russian, etc.

## Usage

```bash
# Set API keys
export HUGGINGFACE_API_KEY=your_key
export GEMINI_API_KEY=your_key

# Run service
go run cmd/server/main.go
```

## Endpoints

### Detection
- `POST /v1/detect` - Detect prompt injection with fallback
- `GET /v1/metrics` - Performance metrics
- `GET /v1/diagnose-llm` - Model status and diagnostics

### Circuit Breaker Management
- `GET /health` - Service health with circuit breaker status
- `GET /v1/circuit-breakers` - View all circuit breaker states
- `POST /v1/circuit-breakers/:model/reset` - Reset specific circuit breaker

## Example

```bash
curl -X POST http://localhost:3000/v1/detect \
  -d '{"text":"Ignore previous instructions","confidence_threshold":0.7}'
```

Response:
```json
{
  "is_malicious": true,
  "confidence": 0.92,
  "threat_types": ["jailbreak"],
  "processing_time_ms": 45,
  "endpoint": "ProtectAI-DeBERTa-v3"
}
```

## Circuit Breaker States

- **CLOSED**: Model working normally
- **OPEN**: Model failed, using fallback  
- **HALF_OPEN**: Testing if model recovered

## Fallback Strategy

1. **ProtectAI DeBERTa** (fastest, specialized)
2. **Meta Llama Guard** (fast, reliable) 
3. **Gemini 2.0 Flash** (smartest, different provider)
4. **HTTP 503** (clean failure with retry-after)