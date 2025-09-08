"""
Socket.IO server implementation for real-time dashboard functionality
"""

import socketio
import logging
from typing import Optional
from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Global Socket.IO server instance
sio: Optional[socketio.AsyncServer] = None

async def create_socketio_server() -> socketio.AsyncServer:
    """Create and configure Socket.IO server"""
    global sio
    
    settings = get_settings()
    
    # CORS configuration for Socket.IO
    cors_origins = ["http://localhost:3000", "http://localhost:3001"]  # Next.js dev servers
    if hasattr(settings, 'websocket_cors_origins') and settings.websocket_cors_origins:
        cors_origins = settings.websocket_cors_origins.split(',')
    
    # Create Socket.IO server
    sio = socketio.AsyncServer(
        async_mode='asgi',
        cors_allowed_origins=cors_origins,
        logger=True,
        engineio_logger=False,  # Reduce noise in logs
        ping_timeout=30,
        ping_interval=25
    )
    
    logger.info("Socket.IO server created", cors_origins=cors_origins)
    return sio

async def get_socketio_server() -> socketio.AsyncServer:
    """Get the global Socket.IO server instance"""
    global sio
    if sio is None:
        sio = await create_socketio_server()
    return sio

def create_socketio_app():
    """Create Socket.IO ASGI app for mounting"""
    # Create a placeholder that will be replaced during startup
    placeholder_sio = socketio.AsyncServer(async_mode='asgi')
    return socketio.ASGIApp(placeholder_sio, socketio_path='/socket.io')