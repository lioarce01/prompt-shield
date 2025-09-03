"""
Database configuration and session management

SQLAlchemy setup with async support for PostgreSQL database
including connection pooling and health checks.
"""
import asyncio
from typing import AsyncGenerator, Optional
from contextlib import asynccontextmanager

import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import text
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings

logger = structlog.get_logger()
settings = get_settings()

# Create base class for models
Base = declarative_base()

# Global engine and session factory
engine: Optional[object] = None
SessionLocal: Optional[async_sessionmaker] = None


async def create_engine():
    """Create database engine with connection pooling"""
    global engine, SessionLocal
    
    try:
        # Convert postgres:// to postgresql+asyncpg://
        db_url = settings.DATABASE_URL
        if db_url.startswith("postgresql://") and "+asyncpg" not in db_url:
            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif "sqlite" in db_url:
            # For testing with SQLite, use aiosqlite
            if "+aiosqlite" not in db_url:
                db_url = db_url.replace("sqlite://", "sqlite+aiosqlite://", 1)
        
        # Create async engine
        engine = create_async_engine(
            db_url,
            echo=settings.DATABASE_ECHO,
            pool_pre_ping=True,
            pool_recycle=3600,
            pool_size=10,
            max_overflow=20,
            # Use StaticPool for SQLite testing
            poolclass=StaticPool if "sqlite" in db_url else None,
            connect_args={"check_same_thread": False} if "sqlite" in db_url else {}
        )
        
        # Create session factory
        SessionLocal = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
        
        logger.info("Database engine created", database_url=db_url.split("@")[0] + "@***")
        
    except Exception as e:
        logger.error("Failed to create database engine", error=str(e))
        raise


async def init_db():
    """Initialize database connection and create tables"""
    try:
        await create_engine()
        
        # Test database connection
        await test_db_connection()
        
        # Create tables (in production, use Alembic migrations instead)
        if settings.DEBUG:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created")
            
    except Exception as e:
        logger.error("Failed to initialize database", error=str(e))
        raise


async def test_db_connection() -> bool:
    """Test database connection health"""
    try:
        async with SessionLocal() as session:
            await session.execute(text("SELECT 1"))
            logger.info("Database connection test successful")
            return True
            
    except Exception as e:
        logger.error("Database connection test failed", error=str(e))
        return False


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session with proper cleanup"""
    if not SessionLocal:
        await create_engine()
    
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error("Database session error", error=str(e))
            raise
        finally:
            await session.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for database sessions"""
    async with get_db_session() as session:
        yield session


async def close_db():
    """Close database connections"""
    global engine
    if engine:
        await engine.dispose()
        logger.info("Database connections closed")


# Database health check for monitoring
async def db_health_check() -> dict:
    """Check database health for monitoring endpoints"""
    try:
        start_time = asyncio.get_event_loop().time()
        success = await test_db_connection()
        response_time = (asyncio.get_event_loop().time() - start_time) * 1000
        
        return {
            "status": "healthy" if success else "unhealthy",
            "response_time_ms": round(response_time, 2),
            "connection_pool": {
                "size": engine.pool.size() if engine else 0,
                "checked_in": engine.pool.checkedin() if engine else 0,
                "checked_out": engine.pool.checkedout() if engine else 0
            } if engine else None
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }