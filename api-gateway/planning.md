# API Gateway Planning Document

## Project Overview

FastAPI-based gateway service that provides enterprise-ready access to the Go detection engine with authentication, rate limiting, analytics, and developer-friendly features.

## Architecture & Sub-Agent Responsibilities

### 🐍 python-ml-api-developer
**Primary Owner: FastAPI Gateway Core**

**Responsibilities:**
- FastAPI application architecture with async/await patterns
- Request/response models with Pydantic validation
- Integration with Go detection engine via HTTP client
- Batch processing with background tasks (Celery/RQ)
- OpenAPI documentation and SDK auto-generation
- Exception handling and error responses
- Health checks and service monitoring endpoints

**Key Technologies:**
- FastAPI, Pydantic, Uvicorn
- AsyncIO, httpx for Go service communication
- Background task processing
- OpenAPI/Swagger documentation

---

### 🏗️ project-architect  
**System Architecture & Integration Patterns**

**Responsibilities:**
- Overall system architecture and service communication patterns
- Database schema design for users, API keys, usage tracking
- Caching strategy (Redis) for performance optimization
- Message queue architecture for webhook delivery
- Microservices communication patterns
- Scalability and performance optimization strategies
- Integration patterns with external systems

**Key Decisions:**
- Service-to-service communication protocols
- Data persistence strategies
- Caching and performance optimization
- Horizontal scaling architecture

---

### 🚀 devops-infrastructure-engineer
**Deployment & Operations**

**Responsibilities:**
- Docker containerization for FastAPI service
- Kubernetes deployment manifests and Helm charts
- CI/CD pipeline setup for automated testing/deployment
- Service discovery and load balancing configuration
- Monitoring, logging, and observability (Prometheus, Grafana)
- Database migrations and backup strategies
- Environment configuration management

**Infrastructure Components:**
- Container orchestration
- Service mesh configuration
- Monitoring and alerting
- Database operations
- Secret management

---

### 🛡️ ai-security-researcher
**Security Architecture & Validation**

**Responsibilities:**
- API security best practices implementation
- Authentication and authorization mechanisms
- Rate limiting and DDoS protection strategies
- Input validation and sanitization
- Security testing and vulnerability assessment
- Secure API key generation and management
- Audit logging for security compliance

**Security Focus:**
- API endpoint protection
- Request validation and sanitization
- Secure credential management
- Compliance with security standards

---

### 📚 opensource-community-builder
**Developer Experience & Documentation**

**Responsibilities:**
- Comprehensive API documentation and tutorials
- SDK examples in multiple programming languages
- Integration guides for popular frameworks
- Community contribution guidelines
- Developer onboarding documentation
- API versioning and backward compatibility strategy

**Deliverables:**
- Developer portal and documentation
- Code examples and tutorials
- Community engagement strategy
- SDK and integration samples

## Technical Architecture

### Core Components

```python
api-gateway/
├── app/
│   ├── main.py                 # FastAPI app entry point
│   ├── api/
│   │   ├── v1/
│   │   │   ├── detection.py    # Detection endpoints
│   │   │   ├── auth.py         # Authentication endpoints
│   │   │   ├── webhooks.py     # Webhook management
│   │   │   └── admin.py        # Admin dashboard
│   │   └── dependencies.py     # Shared dependencies
│   ├── core/
│   │   ├── config.py          # Configuration management
│   │   ├── security.py        # Security utilities
│   │   └── database.py        # Database connections
│   ├── models/
│   │   ├── user.py           # User and API key models
│   │   ├── detection.py      # Detection request/response models
│   │   └── webhook.py        # Webhook models
│   ├── services/
│   │   ├── detection_client.py # Go service client
│   │   ├── rate_limiter.py    # Rate limiting service
│   │   ├── webhook_delivery.py # Webhook delivery service
│   │   └── analytics.py       # Usage analytics
│   └── utils/
│       ├── validators.py      # Input validation
│       └── helpers.py         # Utility functions
├── tests/
├── docker/
├── docs/
├── requirements.txt
└── README.md
```

## API Endpoint Design

### Core Detection API

```python
# Primary detection endpoint
POST /v1/detect
{
  "text": "string",
  "config": {
    "confidence_threshold": 0.7,
    "include_reasoning": true
  },
  "webhook_url": "https://client.com/webhook" # optional
}

# Batch processing
POST /v1/detect/batch
{
  "requests": [
    {"id": "req1", "text": "..."},
    {"id": "req2", "text": "..."}
  ],
  "webhook_url": "https://client.com/batch-complete"
}

# Async detection with webhooks
POST /v1/detect/async
{
  "text": "string",
  "webhook_url": "https://client.com/webhook",
  "metadata": {"user_id": "123", "session": "abc"}
}
```

### Authentication & Management

```python
# API key management
POST /auth/register        # Create new API key
GET  /auth/profile         # Get usage statistics
POST /auth/rotate-key      # Rotate API key
DELETE /auth/revoke        # Revoke API key

# Webhook management
POST /webhooks/register    # Register webhook endpoint
GET  /webhooks/list        # List registered webhooks
POST /webhooks/test        # Test webhook delivery
DELETE /webhooks/{id}      # Remove webhook
```

### Admin & Analytics

```python
# Usage analytics
GET /admin/stats           # System-wide statistics
GET /admin/users           # User management
GET /admin/usage/{api_key} # Per-client usage stats

# System health
GET /health                # Service health check
GET /metrics               # Prometheus metrics
```

## Database Schema

### User & Authentication

```sql
-- API Keys and Users
CREATE TABLE api_keys (
    id UUID PRIMARY KEY,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    rate_limit_per_minute INTEGER DEFAULT 60,
    rate_limit_per_day INTEGER DEFAULT 10000
);

-- Usage tracking
CREATE TABLE usage_logs (
    id BIGSERIAL PRIMARY KEY,
    api_key_id UUID REFERENCES api_keys(id),
    endpoint VARCHAR(50),
    request_size INTEGER,
    response_time_ms INTEGER,
    is_malicious BOOLEAN,
    confidence FLOAT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Webhook System

```sql
-- Webhook configurations
CREATE TABLE webhooks (
    id UUID PRIMARY KEY,
    api_key_id UUID REFERENCES api_keys(id),
    url VARCHAR(500) NOT NULL,
    events TEXT[] DEFAULT '{"detection_complete"}',
    secret_token VARCHAR(64),
    is_active BOOLEAN DEFAULT TRUE,
    retry_count INTEGER DEFAULT 3,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Webhook delivery tracking
CREATE TABLE webhook_deliveries (
    id BIGSERIAL PRIMARY KEY,
    webhook_id UUID REFERENCES webhooks(id),
    payload JSONB,
    http_status INTEGER,
    response_body TEXT,
    attempt_count INTEGER DEFAULT 1,
    delivered_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## Integration with Go Detection Engine

### Service Communication

```python
class DetectionClient:
    def __init__(self, base_url: str = "http://detection-engine:8080"):
        self.client = httpx.AsyncClient(base_url=base_url)
    
    async def detect_prompt_injection(
        self, 
        text: str, 
        confidence_threshold: float = 0.6
    ) -> DetectionResponse:
        response = await self.client.post(
            "/v1/detect",
            json={
                "text": text,
                "config": {
                    "confidence_threshold": confidence_threshold,
                    "detailed_response": True
                }
            }
        )
        return DetectionResponse.parse_obj(response.json())
```

### Error Handling & Fallbacks

```python
class DetectionService:
    async def analyze_with_fallback(self, text: str) -> DetectionResult:
        try:
            # Primary Go detection engine
            return await self.detection_client.detect(text)
        except httpx.ConnectError:
            # Fallback to cached/simplified detection
            return await self.fallback_detection(text)
        except httpx.TimeoutException:
            # Handle timeout gracefully
            return DetectionResult(
                is_malicious=False,
                confidence=0.5,
                reason="Detection service timeout - flagged for manual review"
            )
```

## Performance & Scalability

### Caching Strategy

```python
# Redis caching for frequent requests
@cached(expire=300)  # 5-minute cache
async def detect_with_cache(text_hash: str, text: str) -> DetectionResult:
    return await detection_service.analyze(text)

# Rate limiting with Redis
async def check_rate_limit(api_key: str) -> bool:
    key = f"rate_limit:{api_key}:{datetime.now().minute}"
    current = await redis.incr(key)
    if current == 1:
        await redis.expire(key, 60)
    return current <= rate_limit
```

### Background Processing

```python
# Celery tasks for heavy operations
@celery.task
def process_batch_detection(request_ids: List[str]):
    for req_id in request_ids:
        result = detection_service.analyze(get_request(req_id))
        deliver_webhook(req_id, result)

# Async webhook delivery
@celery.task(bind=True, max_retries=3)
def deliver_webhook(self, webhook_url: str, payload: dict):
    try:
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
    except Exception as exc:
        raise self.retry(exc=exc, countdown=2 ** self.request.retries)
```

## Security Implementation

### Authentication Middleware

```python
class APIKeyAuth:
    async def __call__(self, request: Request):
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            raise HTTPException(401, "API key required")
        
        key_data = await verify_api_key(api_key)
        if not key_data or not key_data.is_active:
            raise HTTPException(401, "Invalid API key")
        
        # Rate limiting check
        if not await check_rate_limit(key_data.id):
            raise HTTPException(429, "Rate limit exceeded")
        
        request.state.api_key = key_data
        return request
```

### Input Validation

```python
class DetectionRequest(BaseModel):
    text: constr(max_length=10000, min_length=1)
    config: Optional[DetectionConfig] = DetectionConfig()
    webhook_url: Optional[HttpUrl] = None
    metadata: Optional[Dict[str, Any]] = None

    @validator('text')
    def validate_text_content(cls, v):
        # Prevent binary data, null bytes
        if '\x00' in v or not v.isprintable():
            raise ValueError('Text contains invalid characters')
        return v
```

## Implementation Phases

### Phase 1: Core Gateway (Week 1-2)
**Led by: python-ml-api-developer**
- Basic FastAPI application setup
- Core detection endpoint proxying Go service
- Request/response validation with Pydantic
- Basic error handling and logging

### Phase 2: Authentication & Rate Limiting (Week 2-3)
**Led by: ai-security-researcher**
- API key generation and management system
- Rate limiting with Redis
- Authentication middleware
- Security headers and input validation

### Phase 3: Database & Persistence (Week 3-4)
**Led by: project-architect**
- PostgreSQL database setup with SQLAlchemy
- User and usage tracking models
- Database migration system
- Connection pooling and optimization

### Phase 4: Webhooks & Async Processing (Week 4-5)
**Led by: python-ml-api-developer**
- Webhook registration and delivery system
- Background task processing with Celery
- Batch detection endpoints
- Retry logic and error handling

### Phase 5: Deployment & Monitoring (Week 5-6)
**Led by: devops-infrastructure-engineer**
- Docker containerization
- Kubernetes deployment manifests
- Monitoring and logging setup
- CI/CD pipeline implementation

### Phase 6: Documentation & SDKs (Week 6-7)
**Led by: opensource-community-builder**
- Comprehensive API documentation
- Python SDK development
- Integration examples and tutorials
- Developer portal setup

## Success Metrics

### Performance Targets
- **Latency**: <100ms additional overhead over Go service
- **Throughput**: Handle 1000+ requests/second
- **Availability**: 99.9% uptime with proper health checks
- **Scalability**: Horizontal scaling with load balancing

### Developer Experience
- **Onboarding**: <5 minutes from API key to first successful request
- **Documentation**: Complete OpenAPI specification
- **SDKs**: Python, JavaScript, and curl examples
- **Support**: Clear error messages and troubleshooting guides

### Business Metrics
- **API Adoption**: Track active API keys and usage growth
- **Integration Success**: Monitor webhook delivery rates
- **Performance**: Track response times and error rates
- **Community**: GitHub stars, contributions, and issues

## Risk Mitigation

### Technical Risks
- **Go Service Dependency**: Implement fallback mechanisms and circuit breakers
- **Database Performance**: Use connection pooling and query optimization
- **Rate Limiting**: Implement distributed rate limiting with Redis
- **Security**: Regular security audits and vulnerability scanning

### Operational Risks
- **Scaling**: Design for horizontal scaling from day one
- **Monitoring**: Comprehensive logging and alerting
- **Backup**: Automated database backups and disaster recovery
- **Documentation**: Keep documentation in sync with code changes

---

This planning document provides a comprehensive roadmap for building a production-ready FastAPI gateway that leverages our specialized sub-agents' expertise while integrating seamlessly with the Go detection engine.