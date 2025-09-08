"""
Tenant models - Multi-tenant architecture
Clean implementation without legacy support
"""

from sqlalchemy import Column, String, DateTime, Boolean, Integer, BigInteger, Text, JSON, Date, Numeric, DECIMAL
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy import ForeignKey, UniqueConstraint, CheckConstraint
from app.core.database import Base
import uuid
from datetime import datetime
from typing import Optional, Dict, Any


class Tenant(Base):
    """
    Core tenant model - represents an organization/company
    Now supports JWT authentication as User entity
    Each tenant gets exactly ONE API key
    """
    __tablename__ = "tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=False, unique=True)
    company_name = Column(String(255), nullable=True)
    
    # JWT Authentication fields (NEW)
    password_hash = Column(String(255), nullable=True)  # Nullable for backward compatibility
    role = Column(String(20), nullable=False, default='user')  # 'admin', 'user'
    last_login = Column(DateTime(timezone=True), nullable=True)
    is_email_verified = Column(Boolean, nullable=False, default=False)
    
    # Status management
    status = Column(String(20), nullable=False, default='active')
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Tenant-specific settings
    settings = Column(JSONB, nullable=False, default={
        "detection_threshold": 0.7,
        "rate_limit_per_minute": 1000,
        "cache_enabled": True,
        "webhook_url": None,
        "notification_email": None
    })
    
    # Relationships
    api_key = relationship("TenantAPIKey", back_populates="tenant", uselist=False, cascade="all, delete-orphan")
    requests = relationship("TenantRequest", back_populates="tenant", cascade="all, delete-orphan")
    daily_usage = relationship("TenantUsageDaily", back_populates="tenant", cascade="all, delete-orphan")
    
    # Constraints
    __table_args__ = (
        CheckConstraint("length(trim(name)) > 0", name="tenants_name_not_empty"),
        CheckConstraint("email ~* '^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+[.][A-Za-z]+$'", name="tenants_email_valid"),
        CheckConstraint("status IN ('active', 'suspended', 'trial')", name="tenants_status_valid"),
        CheckConstraint("role IN ('admin', 'user')", name="tenants_role_valid"),  # NEW constraint
    )
    
    def __repr__(self):
        return f"<Tenant(id={self.id}, name='{self.name}', status='{self.status}')>"
    
    @property
    def is_active(self) -> bool:
        """Check if tenant is active"""
        return self.status == 'active'
    
    @property
    def detection_threshold(self) -> float:
        """Get tenant-specific detection threshold"""
        return self.settings.get('detection_threshold', 0.7)
    
    @property
    def rate_limit_per_minute(self) -> int:
        """Get tenant-specific rate limit"""
        return self.settings.get('rate_limit_per_minute', 1000)
    
    def update_settings(self, new_settings: Dict[str, Any]) -> None:
        """Update tenant settings"""
        current_settings = self.settings.copy()
        current_settings.update(new_settings)
        self.settings = current_settings
    
    # NEW: JWT Authentication methods
    @property
    def is_authenticated(self) -> bool:
        """Check if tenant has password set (can login with JWT)"""
        return self.password_hash is not None
    
    @property 
    def is_admin(self) -> bool:
        """Check if tenant has admin role"""
        return self.role == 'admin'
    
    def update_last_login(self) -> None:
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
    
    def can_generate_api_key(self) -> bool:
        """Check if tenant is allowed to generate API keys"""
        return self.is_active and self.is_authenticated
    
    def to_jwt_payload(self) -> Dict[str, Any]:
        """Generate JWT payload for this tenant"""
        return {
            'sub': str(self.id),  # Subject (tenant ID)
            'email': self.email,
            'name': self.name,
            'role': self.role,
            'company': self.company_name,
            'verified': self.is_email_verified,
            'active': self.is_active
        }


class TenantAPIKey(Base):
    """
    API Keys for tenants - ONE key per tenant
    """
    __tablename__ = "tenant_api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    
    # Key details
    key_prefix = Column(String(20), nullable=False)  # pid_12345678
    key_hash = Column(String(255), nullable=False)   # bcrypt hash
    
    # Metadata
    name = Column(String(255), nullable=False, default='Primary API Key')
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    
    # Relationship
    tenant = relationship("Tenant", back_populates="api_key")
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('tenant_id', name='one_api_key_per_tenant'),
        CheckConstraint("key_prefix ~ '^pid_[a-f0-9]{8}$'", name="key_prefix_format"),
    )
    
    def __repr__(self):
        return f"<TenantAPIKey(id={self.id}, tenant_id={self.tenant_id}, prefix='{self.key_prefix}')>"
    
    def update_last_used(self) -> None:
        """Update last used timestamp"""
        self.last_used_at = datetime.utcnow()


class TenantRequest(Base):
    """
    Individual request logs with tenant context
    Used for detailed analytics and debugging
    """
    __tablename__ = "tenant_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    
    # Request identification
    request_id = Column(String(50), nullable=False)  # Correlation ID
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Input data
    text_length = Column(Integer, nullable=False)
    text_hash = Column(String(64), nullable=True)  # SHA-256 for deduplication
    
    # Detection results
    is_malicious = Column(Boolean, nullable=False)
    confidence = Column(DECIMAL(5, 3), nullable=False)
    threat_types = Column(JSONB, nullable=False, default=[])
    
    # Performance metrics
    processing_time_ms = Column(DECIMAL(10, 3), nullable=False)
    cache_hit = Column(Boolean, nullable=False, default=False)
    model_used = Column(String(100), nullable=True)
    
    # Additional context
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(INET, nullable=True)
    
    # Relationship
    tenant = relationship("Tenant", back_populates="requests")
    
    # Constraints
    __table_args__ = (
        CheckConstraint("text_length > 0", name="text_length_positive"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
        CheckConstraint("processing_time_ms >= 0", name="processing_time_positive"),
    )
    
    def __repr__(self):
        return f"<TenantRequest(id={self.id}, tenant_id={self.tenant_id}, malicious={self.is_malicious})>"


class TenantUsageDaily(Base):
    """
    Daily usage aggregation per tenant
    Used for analytics, dashboards, and billing
    """
    __tablename__ = "tenant_usage_daily"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False)
    date = Column(Date, nullable=False)
    
    # Request counters (matching actual DB schema)
    total_requests = Column(Integer, nullable=False, default=0)
    malicious_requests = Column(Integer, nullable=False, default=0)
    safe_requests = Column(Integer, nullable=False, default=0)
    
    # Performance metrics (matching actual DB schema)
    avg_processing_time_ms = Column(DECIMAL(8, 2), nullable=True)
    max_processing_time_ms = Column(Integer, nullable=True)
    
    # Cache metrics (matching actual DB schema)
    cache_hits = Column(Integer, nullable=False, default=0)
    
    # Additional metrics (matching actual DB schema)
    avg_confidence = Column(DECIMAL(5, 4), nullable=True)
    
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationship
    tenant = relationship("Tenant", back_populates="daily_usage")
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('tenant_id', 'date', name='one_daily_record_per_tenant'),
        CheckConstraint("total_requests >= 0", name="total_requests_positive"),
        CheckConstraint("malicious_blocked >= 0", name="malicious_blocked_positive"),
        CheckConstraint("safe_allowed >= 0", name="safe_allowed_positive"),
        CheckConstraint("cache_hits >= 0", name="cache_hits_positive"),
        CheckConstraint("cache_misses >= 0", name="cache_misses_positive"),
        CheckConstraint("safe_allowed + malicious_blocked = total_requests", name="requests_sum_matches"),
    )
    
    def __repr__(self):
        return f"<TenantUsageDaily(tenant_id={self.tenant_id}, date={self.date}, requests={self.total_requests})>"
    
    @property
    def block_rate(self) -> float:
        """Calculate percentage of requests blocked"""
        if self.total_requests == 0:
            return 0.0
        return (self.malicious_blocked / self.total_requests) * 100
    
    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate percentage"""
        total_cache_operations = self.cache_hits + self.cache_misses
        if total_cache_operations == 0:
            return 0.0
        return (self.cache_hits / total_cache_operations) * 100