"""
Database models for authentication and user management

SQLAlchemy models for API keys, users, and usage tracking
following the database schema from the planning document.
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, String, Boolean, Integer, DateTime, Text, BigInteger, Float, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base


class APIKey(Base):
    """API key model for authentication and rate limiting"""
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    name = Column(String(100), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    rate_limit_per_minute = Column(Integer, default=60, nullable=False)
    rate_limit_per_day = Column(Integer, default=10000, nullable=False)
    
    # Relationships
    usage_logs = relationship("UsageLog", back_populates="api_key", cascade="all, delete-orphan")
    webhooks = relationship("Webhook", back_populates="api_key", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<APIKey(id={self.id}, name='{self.name}', active={self.is_active})>"
    
    @property
    def masked_id(self) -> str:
        """Return masked ID for logging"""
        str_id = str(self.id)
        return f"{str_id[:8]}...{str_id[-4:]}"


class UsageLog(Base):
    """Usage tracking for API requests"""
    __tablename__ = "usage_logs"
    
    id = Column(BigInteger, primary_key=True, index=True)
    api_key_id = Column(UUID(as_uuid=True), ForeignKey("api_keys.id"), nullable=False, index=True)
    endpoint = Column(String(50), nullable=True, index=True)
    request_size = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    is_malicious = Column(Boolean, nullable=True, index=True)
    confidence = Column(Float, nullable=True)
    threat_types = Column(ARRAY(String), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Additional fields for analytics
    user_agent = Column(String(200), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    status_code = Column(Integer, nullable=True, index=True)
    
    # Relationships
    api_key = relationship("APIKey", back_populates="usage_logs")
    
    def __repr__(self):
        return f"<UsageLog(id={self.id}, endpoint='{self.endpoint}', malicious={self.is_malicious})>"


class Webhook(Base):
    """Webhook configuration for async result delivery"""
    __tablename__ = "webhooks"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    api_key_id = Column(UUID(as_uuid=True), ForeignKey("api_keys.id"), nullable=False, index=True)
    url = Column(String(500), nullable=False)
    events = Column(ARRAY(String), default=["detection_complete"], nullable=False)
    secret_token = Column(String(64), nullable=True)
    description = Column(String(200), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    retry_count = Column(Integer, default=3, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_triggered_at = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    api_key = relationship("APIKey", back_populates="webhooks")
    deliveries = relationship("WebhookDelivery", back_populates="webhook", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Webhook(id={self.id}, url='{self.url}', active={self.is_active})>"
    
    @property
    def masked_secret(self) -> Optional[str]:
        """Return masked secret token"""
        if not self.secret_token:
            return None
        return f"{self.secret_token[:4]}...{self.secret_token[-4:]}"


class WebhookDelivery(Base):
    """Webhook delivery tracking and retry management"""
    __tablename__ = "webhook_deliveries"
    
    id = Column(BigInteger, primary_key=True, index=True)
    webhook_id = Column(UUID(as_uuid=True), ForeignKey("webhooks.id"), nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    payload = Column(Text, nullable=True)  # JSON payload as text
    http_status = Column(Integer, nullable=True, index=True)
    response_body = Column(Text, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    attempt_count = Column(Integer, default=1, nullable=False)
    success = Column(Boolean, nullable=True, index=True)
    error_message = Column(Text, nullable=True)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    next_retry_at = Column(DateTime(timezone=True), nullable=True, index=True)
    
    # Relationships
    webhook = relationship("Webhook", back_populates="deliveries")
    
    def __repr__(self):
        return f"<WebhookDelivery(id={self.id}, webhook_id={self.webhook_id}, success={self.success})>"


# Create indexes for performance (would be handled by Alembic migrations in production)
"""
Additional indexes for high-performance queries:

CREATE INDEX CONCURRENTLY idx_usage_logs_api_key_created 
ON usage_logs (api_key_id, created_at DESC);

CREATE INDEX CONCURRENTLY idx_usage_logs_created_malicious 
ON usage_logs (created_at DESC, is_malicious) 
WHERE is_malicious IS NOT NULL;

CREATE INDEX CONCURRENTLY idx_webhook_deliveries_created_success 
ON webhook_deliveries (created_at DESC, success);

CREATE INDEX CONCURRENTLY idx_webhook_deliveries_retry 
ON webhook_deliveries (next_retry_at) 
WHERE next_retry_at IS NOT NULL;
"""