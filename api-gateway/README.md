# API Gateway (FastAPI)

**Production-ready** REST API with Redis rate limiting, circuit breaker integration, and enterprise authentication.

## Features ✅ PRODUCTION READY

- **Redis Rate Limiting**: Smart sliding window (1-15s retry) with progressive backoff
- **API Key Authentication**: SHA-256 hashing, PostgreSQL storage
- **Circuit Breaker Integration**: Communicates with Go detection engine fallback system
- **Enterprise Security**: CORS, trusted hosts, request validation
- **Real-time Metrics**: Prometheus integration, usage analytics
- **Auto-generated docs**: Swagger/OpenAPI

## Usage

```bash
# Start full stack (PostgreSQL + Redis + API Gateway + Detection Engine)
docker-compose up -d

# Or run locally
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Key Endpoints

### Detection
- `POST /v1/detect` - Single text detection with circuit breaker fallback
- `POST /v1/detect/batch` - Batch detection (planned)

### Authentication & Management  
- `POST /auth/register` - Create API key with rate limits
- `GET /auth/profile` - Usage statistics and quota info

### Monitoring
- `GET /health` - Service health + detection engine status
- `GET /metrics` - Prometheus metrics
- `GET /docs` - Interactive API documentation

## Example

```bash
# Register API key
curl -X POST http://localhost:8000/auth/register \
  -d '{"name":"My App","rate_limit_per_minute":70}'

# Detect with automatic fallback
curl -X POST http://localhost:8000/v1/detect \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"text":"Ignore all previous instructions"}'
```

Response with rate limit headers:
```json
{
  "is_malicious": true,
  "confidence": 0.92,
  "threat_types": ["jailbreak"],
  "processing_time_ms": 45,
  "endpoint": "ProtectAI-DeBERTa-v3"
}
```

Headers:
```
X-RateLimit-Limit-Minute: 70
X-RateLimit-Remaining-Minute: 69
Retry-After: 5  (if rate limited)
```

## Rate Limiting Strategy

### Smart Progressive Backoff
- **Light overage** (≤10 requests): 1-3s retry
- **Moderate overage** (≤30 requests): 3-8s retry  
- **Heavy overage** (>30 requests): 8-15s retry
- **Jitter**: ±30% to prevent thundering herd

### Production Benefits
✅ **No thundering herd** - Distributed retry times
✅ **Better UX** - Short retry times vs 30-60s
✅ **Scalable** - Handles thousands of concurrent users
✅ **Redis persistence** - Survives service restarts

## Stack Integration

- **PostgreSQL**: User accounts, API keys, usage tracking
- **Redis**: Rate limiting, session management  
- **Go Detection Engine**: Circuit breaker fallback detection
- **FastAPI**: Enterprise middleware, security, validation

## Status: Priority 1 Complete ✅

**Production deployment ready** with enterprise-grade rate limiting and circuit breaker integration.