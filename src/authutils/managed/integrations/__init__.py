"""
Framework integrations for authentication.

This package provides framework-specific implementations for authentication flows,
currently supporting FastAPI for both REST API and WebSocket authentication.

The integrations package allows the core authentication functionality to be
easily integrated into different web frameworks while maintaining a consistent
interface.
"""

from .fastapi import (
    create_fastapi_auth_dependency,  # Factory for creating FastAPI auth dependencies
)

from .socketio import (
    create_socketio_authenticator,  # Factory for creating Socket.IO auth handlers
)

__all__ = [
    # FastAPI integrations
    'create_fastapi_auth_dependency',  # Factory for creating FastAPI auth dependencies
    'create_socketio_authenticator',  # Factory for creating Socket.IO auth handlers
]