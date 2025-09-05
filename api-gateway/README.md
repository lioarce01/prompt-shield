# API Gateway (FastAPI)

Enterprise-ready REST API for prompt injection detection with authentication and rate limiting.

## Features

- **API key authentication** with SHA-256 hashing
- **Rate limiting** per client
- **Webhook delivery** for async results
- **Usage analytics** and metrics
- **Auto-generated docs** (Swagger/OpenAPI)

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Run service
uvicorn app.main:app --reload --port 8000
```

## Key Endpoints

- `POST /v1/detect` - Single text detection
- `POST /v1/detect/batch` - Batch detection
- `POST /auth/register` - Create API key
- `GET /auth/profile` - Usage statistics
- `GET /docs` - Interactive API documentation

## Example

```bash
# Register API key
curl -X POST http://localhost:8000/auth/register \
  -d '{"name":"My App","rate_limit_per_minute":100}'

# Detect threat
curl -X POST http://localhost:8000/v1/detect \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"text":"Ignore all previous instructions"}'
```

## Authentication Status

### ✅ Working Endpoints (Real Database Integration)
- **POST /auth/register** - Create API key ✅
- **GET /auth/profile** - Get usage statistics ✅

### 🚧 Pending Endpoints (Still Mock Data)
- **POST /auth/rotate-key** - Rotate API key to new value
- **DELETE /auth/revoke** - Revoke API key permanently  
- **GET /auth/validate** - Validate API key status

**Next Steps:** Update remaining endpoints to use real PostgreSQL database integration instead of mock responses.

## Documentation

- Interactive docs: http://localhost:8000/docs
- Testing guide: `TESTING_GUIDE.md`
- Full API spec: `docs/swagger.yaml`