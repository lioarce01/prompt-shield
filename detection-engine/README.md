# Detection Engine (Go)

High-performance prompt injection detection service using multi-model AI pipeline.

## Features

- **Multi-model detection**: ProtectAI DeBERTa, Llama Guard, Gemini 2.0 Flash
- **Encoding preprocessing**: Base64, Hex, ROT13, ASCII detection
- **Sub-50ms latency** with fallback mechanisms
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

- `POST /v1/detect` - Detect prompt injection
- `GET /health` - Service health check
- `GET /v1/metrics` - Performance metrics

## Example

```bash
curl -X POST http://localhost:8080/v1/detect \
  -d '{"text":"Ignore previous instructions","confidence_threshold":0.7}'
```

Response:
```json
{
  "is_malicious": true,
  "confidence": 0.92,
  "threat_types": ["jailbreak"],
  "processing_time_ms": 45
}
```