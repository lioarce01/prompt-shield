"""
Configuration management for the API Gateway

Uses pydantic-settings for environment variable management
with validation and type conversion.
"""
from typing import List, Optional
from pydantic import BaseModel, Field, validator
from pydantic_settings import BaseSettings


class DatabaseSettings(BaseModel):
    """Database configuration"""
    url: str = Field(default="postgresql://postgres:postgres@localhost:5432/prompt_defense")
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


class Settings(BaseSettings):
    """Main application settings"""
    
    # Application info
    VERSION: str = Field(default="1.0.0")
    DEBUG: bool = Field(default=False)
    
    # API Configuration
    API_PREFIX: str = Field(default="/api/v1")
    DETECTION_ENGINE_URL: str = Field(default="http://localhost:8080")
    
    # Server configuration
    HOST: str = Field(default="0.0.0.0")
    PORT: int = Field(default=8000)
    WORKERS: int = Field(default=1)
    
    # Security
    ALLOWED_HOSTS: List[str] = Field(default=["*"])
    CORS_ORIGINS: List[str] = Field(default=["*"])
    
    # Database
    DATABASE_URL: str = Field(default="postgresql://postgres:postgres@localhost:5432/prompt_defense")
    DATABASE_ECHO: bool = Field(default=False)
    
    # Redis
    REDIS_URL: str = Field(default="redis://localhost:6379/0")
    
    # Security
    SECRET_KEY: str = Field(..., description="Secret key for JWT signing")
    
    # Detection settings
    DEFAULT_CONFIDENCE_THRESHOLD: float = Field(default=0.6)
    MAX_TEXT_LENGTH: int = Field(default=10000)
    MAX_BATCH_SIZE: int = Field(default=100)
    
    # Rate limiting
    DEFAULT_RATE_LIMIT_PER_MINUTE: int = Field(default=60)
    DEFAULT_RATE_LIMIT_PER_DAY: int = Field(default=10000)
    
    # Webhook settings
    WEBHOOK_MAX_RETRIES: int = Field(default=3)
    WEBHOOK_TIMEOUT: int = Field(default=10)
    
    # Celery (for background tasks)
    CELERY_BROKER_URL: str = Field(default="redis://localhost:6379/1")
    CELERY_RESULT_BACKEND: str = Field(default="redis://localhost:6379/1")
    
    @validator('ALLOWED_HOSTS', 'CORS_ORIGINS', pre=True)
    def parse_list_from_string(cls, v):
        """Parse comma-separated strings into lists"""
        if isinstance(v, str):
            return [item.strip() for item in v.split(',') if item.strip()]
        return v
    
    @validator('SECRET_KEY')
    def validate_secret_key(cls, v):
        """Ensure secret key is sufficiently complex"""
        if len(v) < 32:
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

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get application settings (singleton pattern)"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings