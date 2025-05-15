"""
AuthUtils - A Python library for handling OAuth2/OpenID Connect authentication flows.

This package provides a framework-agnostic implementation of OAuth2/OpenID Connect
authentication flows, with built-in support for FastAPI integration.

Example:
    ```python
    from authutils import BackendAuthProviderRegistry, GoogleAuthProvider
    from authutils import LocalPKCEStorage, LocalJWKSStorage
    from authutils import create_fastapi_auth_dependency, create_fastapi_websocket_authenticator

    # Initialize the registry with storage implementations
    registry = BackendAuthProviderRegistry(
        pkce_storage=LocalPKCEStorage(),
        jwks_storage=LocalJWKSStorage()
    )

    # Register providers
    registry.register_provider(GoogleAuthProvider(
        client_id="your-client-id",
        client_secret="your-client-secret"
    ))

    # Create FastAPI auth dependency
    auth_dependency = create_fastapi_auth_dependency(registry)
    
    # Create FastAPI WebSocket authenticator
    websocket_auth = create_fastapi_websocket_authenticator(registry)
    ```
"""

__version__ = "0.1.0"
__author__ = "Evan Vera"
__license__ = "MIT"

# Core components
from .managed.registry import BackendAuthProviderRegistry
from .managed.providers import GoogleAuthProvider
from .managed.storage import LocalPKCEStorage, LocalJWKSStorage
from .common.types.constants import GrantTypeEnum
from .managed.models import ProviderTypeEnum, TokenRequest

# Auth flow functions
from .managed.core.auth_flow import initiate_auth_flow, process_token_exchange

# Framework integrations
from .managed.integrations.fastapi import (
    create_fastapi_auth_dependency,  # Factory for creating FastAPI auth dependencies
)
from .managed.integrations.socketio import (
    create_socketio_authenticator,  # Factory for creating Socket.IO auth handlers
)

# Define public API
__all__ = [
    # Core components
    'BackendAuthProviderRegistry',
    'GoogleAuthProvider',
    'LocalPKCEStorage',
    'LocalJWKSStorage',
    'GrantTypeEnum',
    'ProviderTypeEnum',
    'TokenRequest',
    
    # Auth flow functions
    'initiate_auth_flow',
    'process_token_exchange',
    
    # Framework integrations
    'create_fastapi_auth_dependency',  # Factory for creating FastAPI auth dependencies
    'create_socketio_authenticator',  # Factory for creating Socket.IO auth handlers
]