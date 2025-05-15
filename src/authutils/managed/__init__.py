"""
Managed authentication module.

This module provides managed authentication functionality:
- Core authentication flows
- Provider integrations
- Storage implementations
- Framework integrations
"""

from .core import (
    initiate_auth_flow,
    process_token_exchange,
    exchange_authorization_code,
    exchange_refresh_token,
    verify_id_token
)
from .models import (
    ProviderTypeEnum,
    GrantTypeEnum,
    TokenRequest,
    AccessTokenRequestInternal,
    RefreshTokenRequestInternal,
    TokenResponse,
    ProviderErrorResponse
)
from .registry import BackendAuthProviderRegistry
from .storage import PKCEStorage, JWKSStorage

# Framework integrations
from .integrations.fastapi import (
    create_fastapi_auth_dependency,  # Factory for creating FastAPI auth dependencies
)
from .integrations.socketio import (
    create_socketio_authenticator,  # Factory for creating Socket.IO auth handlers
)

# Define public API
__all__ = [
    # Core functionality
    'initiate_auth_flow',
    'process_token_exchange',
    'exchange_authorization_code',
    'exchange_refresh_token',
    'verify_id_token',
    
    # Models
    'ProviderTypeEnum',
    'GrantTypeEnum',
    'TokenRequest',
    'AccessTokenRequestInternal',
    'RefreshTokenRequestInternal',
    'TokenResponse',
    'ProviderErrorResponse',
    
    # Providers
    'BackendAuthProviderRegistry',
    
    # Storage
    'PKCEStorage',
    'JWKSStorage',
    
    # Framework integrations
    'create_fastapi_auth_dependency',  # Factory for creating FastAPI auth dependencies
    'create_socketio_authenticator',  # Factory for creating Socket.IO auth handlers
]