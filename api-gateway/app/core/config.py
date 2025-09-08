"""
Configuration management for Multi-Tenant API Gateway

Preserves all original configurations while adding multi-tenant support
"""
from typing import List, Optional, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseModel):
    """Database configuration"""
    url: str = Field(default="postgresql://postgres:postgres@localhost:5432/prompt_shield")
    echo: bool = Field(default=False)
    pool_size: int = Field(default=10)
    max_overflow: int = Field(default=20)


class RedisSettings(BaseModel):
    """Redis configuration for caching and rate limiting"""
    url: str = Field(default="redis://localhost:6379/0")
    max_connections: int = Field(default=20)
    
    # Rate limiting configuration
    default_rate_limit_per_minute: int = Field(default=60)
    default_rate_limit_per_day: int = Field(default=10000)
    rate_limit_window: int = Field(default=60)  # seconds


class SecuritySettings(BaseModel):
    """Security configuration"""
    secret_key: str = Field(..., description="Secret key for JWT signing")
    api_key_length: int = Field(default=32)
    jwt_algorithm: str = Field(default="HS256")
    jwt_expire_minutes: int = Field(default=60 * 24 * 7)  # 1 week
    
    # Password hashing
    bcrypt_rounds: int = Field(default=12)


class WebhookSettings(BaseModel):
    """Webhook delivery configuration"""
    max_retries: int = Field(default=3)
    retry_delay: int = Field(default=2)  # seconds
    timeout: int = Field(default=10)  # seconds
    max_payload_size: int = Field(default=1024 * 1024)  # 1MB


# NEW: Multi-tenant specific settings
class TenantSettings(BaseModel):
    """Multi-tenant configuration"""
    isolation_enabled: bool = Field(default=True)
    default_detection_threshold: float = Field(default=0.7)
    default_rate_limit_per_minute: int = Field(default=1000)
    default_cache_ttl_seconds: int = Field(default=1800)  # 30 minutes
    max_tenants_per_cache: int = Field(default=1000)
    tenant_cache_ttl: int = Field(default=300)  # 5 minutes


class Settings(BaseSettings):
    """Main application settings - Enhanced for multi-tenant"""
    
    # Application info
    VERSION: str = Field(default="2.0.0")  # Updated version for multi-tenant
    DEBUG: bool = Field(default=False)
    
    # API Configuration
    API_PREFIX: str = Field(default="/api/v1")
    DETECTION_ENGINE_URL: str = Field(default="http://localhost:8080")
    
    # Server configuration
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)
    WORKERS: int = Field(default=1)
    
    # Security - Using str type to avoid pydantic-settings JSON parsing
    ALLOWED_HOSTS: str = Field(default="*")
    CORS_ORIGINS: str = Field(default="*")
    
    # Computed properties for list access
    @property
    def allowed_hosts_list(self) -> List[str]:
        """Get ALLOWED_HOSTS as list"""
        return self._parse_host_string(self.ALLOWED_HOSTS)
    
    @property 
    def cors_origins_list(self) -> List[str]:
        """Get CORS_ORIGINS as list"""
        return self._parse_host_string(self.CORS_ORIGINS)
    
    # Database
    DATABASE_URL: str = Field(default="postgresql://postgres:postgres@localhost:5432/prompt_shield")
    DATABASE_ECHO: bool = Field(default=False)
    
    # Redis
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    REDIS_HOST: str = Field(default="localhost")
    REDIS_PORT: int = Field(default=6379)
    REDIS_DB_RATE_LIMIT: int = Field(default=0)  # Database for rate limiting
    REDIS_DB_CACHE: int = Field(default=1)       # Database for caching
    
    # Security
    SECRET_KEY: str = Field(default="your-secret-key-change-in-production", description="Secret key for JWT signing")
    
    # Detection settings
    DEFAULT_CONFIDENCE_THRESHOLD: float = Field(default=0.6)
    MAX_TEXT_LENGTH: int = Field(default=10000)
    MAX_BATCH_SIZE: int = Field(default=100)
    
    # Rate limiting (kept for backwards compatibility)
    DEFAULT_RATE_LIMIT_PER_MINUTE: int = Field(default=60)
    DEFAULT_RATE_LIMIT_PER_DAY: int = Field(default=10000)
    
    # NEW: Multi-tenant specific settings
    TENANT_ISOLATION_ENABLED: bool = Field(default=True)
    TENANT_DEFAULT_DETECTION_THRESHOLD: float = Field(default=0.7)
    TENANT_DEFAULT_RATE_LIMIT_PER_MINUTE: int = Field(default=1000)
    TENANT_DEFAULT_CACHE_TTL_SECONDS: int = Field(default=1800)
    
    # Webhook settings
    WEBHOOK_MAX_RETRIES: int = Field(default=3)
    WEBHOOK_TIMEOUT: int = Field(default=10)
    
    # Caching settings
    CACHE_ENABLED: bool = Field(default=True, description="Enable/disable result caching")
    CACHE_TTL_HIGH_CONFIDENCE: int = Field(default=1800, description="TTL for high confidence results (seconds)")  # 30 minutes
    CACHE_TTL_MEDIUM_CONFIDENCE: int = Field(default=300, description="TTL for medium confidence results (seconds)")  # 5 minutes  
    CACHE_TTL_LOW_CONFIDENCE: int = Field(default=0, description="TTL for low confidence results (seconds)")  # No caching
    CACHE_HIGH_CONFIDENCE_THRESHOLD: float = Field(default=0.9, description="Threshold for high confidence caching")
    CACHE_MEDIUM_CONFIDENCE_THRESHOLD: float = Field(default=0.5, description="Threshold for medium confidence caching")
    
    # Celery (for background tasks)
    CELERY_BROKER_URL: str = Field(default="redis://localhost:6379/1")
    CELERY_RESULT_BACKEND: str = Field(default="redis://localhost:6379/1")
    
    # NEW: Performance and monitoring
    REQUEST_TIMEOUT_SECONDS: int = Field(default=30)
    DETECTION_TIMEOUT_SECONDS: int = Field(default=25)
    LOG_LEVEL: str = Field(default="INFO")
    ANALYTICS_RETENTION_DAYS: int = Field(default=90)
    
    def _parse_host_string(self, value: str) -> List[str]:
        """Helper method to parse comma or space separated host strings"""
        if not value or value == "":
            return ["*"]
        # Handle both comma-separated and space-separated values
        items = []
        for item in value.replace(',', ' ').split():
            item = item.strip()
            if item:
                items.append(item)
        return items if items else ["*"]
    
    @field_validator('SECRET_KEY')
    @classmethod
    def validate_secret_key(cls, v):
        """Ensure secret key is sufficiently complex"""
        if v == "your-secret-key-change-in-production":
            # Allow default for development, but warn
            import os
            if os.getenv("ENVIRONMENT", "development").lower() == "production":
                raise ValueError('SECRET_KEY must be changed for production')
        elif len(v) < 32:
            raise ValueError('SECRET_KEY must be at least 32 characters long')
        return v
    
    @property
    def database(self) -> DatabaseSettings:
        """Get database settings"""
        return DatabaseSettings(
            url=self.DATABASE_URL,
            echo=self.DATABASE_ECHO
        )
    
    @property
    def redis(self) -> RedisSettings:
        """Get Redis settings"""
        return RedisSettings(
            url=self.REDIS_URL,
            default_rate_limit_per_minute=self.DEFAULT_RATE_LIMIT_PER_MINUTE,
            default_rate_limit_per_day=self.DEFAULT_RATE_LIMIT_PER_DAY
        )
    
    @property
    def security(self) -> SecuritySettings:
        """Get security settings"""
        return SecuritySettings(
            secret_key=self.SECRET_KEY
        )
    
    @property
    def webhooks(self) -> WebhookSettings:
        """Get webhook settings"""
        return WebhookSettings(
            max_retries=self.WEBHOOK_MAX_RETRIES,
            timeout=self.WEBHOOK_TIMEOUT
        )
    
    # NEW: Multi-tenant settings property
    @property
    def tenant(self) -> TenantSettings:
        """Get multi-tenant settings"""
        return TenantSettings(
            isolation_enabled=self.TENANT_ISOLATION_ENABLED,
            default_detection_threshold=self.TENANT_DEFAULT_DETECTION_THRESHOLD,
            default_rate_limit_per_minute=self.TENANT_DEFAULT_RATE_LIMIT_PER_MINUTE,
            default_cache_ttl_seconds=self.TENANT_DEFAULT_CACHE_TTL_SECONDS
        )
    
    def validate_config(self) -> bool:
        """Validate critical configuration values"""
        errors = []
        
        # Check database URL
        if not self.DATABASE_URL.startswith(('postgresql://', 'postgresql+asyncpg://')):
            errors.append("DATABASE_URL must be a PostgreSQL connection string")
        
        # Check Redis URL
        if not self.REDIS_URL.startswith('redis://'):
            errors.append("REDIS_URL must be a Redis connection string")
        
        # Check detection engine URL
        if not self.DETECTION_ENGINE_URL.startswith(('http://', 'https://')):
            errors.append("DETECTION_ENGINE_URL must be a valid HTTP URL")
        
        # Check tenant thresholds
        if not 0 <= self.TENANT_DEFAULT_DETECTION_THRESHOLD <= 1:
            errors.append("TENANT_DEFAULT_DETECTION_THRESHOLD must be between 0 and 1")
        
        if self.TENANT_DEFAULT_RATE_LIMIT_PER_MINUTE <= 0:
            errors.append("TENANT_DEFAULT_RATE_LIMIT_PER_MINUTE must be positive")
        
        if errors:
            raise ValueError(f"Configuration errors: {'; '.join(errors)}")
        
        return True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="allow",
        protected_namespaces=()
    )


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get application settings (singleton pattern)"""
    global _settings
    if _settings is None:
        _settings = Settings()
        _settings.validate_config()
    return _settings


# Environment-specific configurations for compatibility
class DevelopmentSettings(Settings):
    """Development environment settings"""
    DEBUG: bool = True
    LOG_LEVEL: str = "DEBUG"
    
    # More lenient settings for development
    TENANT_DEFAULT_RATE_LIMIT_PER_MINUTE: int = 10000
    CORS_ORIGINS: str = "*"


class ProductionSettings(Settings):
    """Production environment settings"""
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    
    # Stricter settings for production
    CORS_ORIGINS: str = ""  # Must be configured explicitly
    
    def validate_config(self) -> bool:
        """Additional production validations"""
        super().validate_config()
        
        if self.SECRET_KEY == "your-secret-key-change-in-production":
            raise ValueError("SECRET_KEY must be changed for production")
        
        if "*" in self.cors_origins_list:
            raise ValueError("CORS_ORIGINS should not include '*' in production")
        
        return True


def get_settings_by_env(env: str = None) -> Settings:
    """Get environment-specific settings"""
    import os
    env = env or os.getenv("ENVIRONMENT", "development").lower()
    
    if env == "production":
        return ProductionSettings()
    elif env == "development":
        return DevelopmentSettings()
    else:
        return Settings()