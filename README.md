# AuthUtils

A modern, framework-agnostic authentication library for Python that provides comprehensive OAuth2/OpenID Connect support with a focus on security and flexibility.

## Features

- **Framework-Agnostic Core**: Core authentication logic is independent of any specific web framework
- **Provider Management**: Centralized registry for managing multiple authentication providers
- **Token Management**: Comprehensive token handling including PKCE, JWKS, and token exchange
- **Framework Integrations**: Built-in support for FastAPI (REST and WebSocket)
- **Storage Flexibility**: Pluggable storage backends for PKCE and JWKS
- **Security First**: Built-in support for PKCE, JWKS, and secure token verification
- **Extensible**: Easy to add new providers and storage backends
- **Consistent Error Handling**: Comprehensive exception hierarchy for clear error handling

## Installation

```bash
pip install authutils
```

## Project Structure

```
src/authutils/
├── __init__.py                 # Package exports and version info
├── common/                     # Shared utilities and types
│   ├── __init__.py            # Common module exports
│   ├── exceptions.py          # Common exception definitions
│   └── types/                 # Shared type definitions
│       ├── __init__.py
│       └── constants.py       # Enums and constants
├── managed/                    # Managed authentication (OAuth2/OIDC)
│   ├── __init__.py            # Managed module exports
│   ├── core/                  # Core authentication logic
│   │   ├── __init__.py
│   │   ├── auth_flow.py      # Auth flow implementation
│   │   ├── exchange.py       # Token exchange logic
│   │   └── verification.py   # Token verification
│   ├── models/               # Data models
│   │   ├── __init__.py
│   │   └── types.py         # Request/response types
│   ├── providers/            # Auth providers
│   │   ├── __init__.py
│   │   ├── base.py          # Base provider interface
│   │   └── google.py        # Google OAuth2 implementation
│   ├── storage/             # Storage implementations
│   │   ├── __init__.py
│   │   ├── base.py         # Storage interfaces
│   │   ├── jwks/           # JWKS storage
│   │   └── pkce/           # PKCE storage
│   └── integrations/        # Framework integrations
│       ├── __init__.py
│       ├── base.py         # Integration interface
│       └── fastapi/        # FastAPI integration
│           ├── __init__.py
│           ├── rest_dependencies.py    # REST API auth
│           └── websocket_auth.py       # WebSocket auth
└── manual/                  # Manual authentication (future)
```

## Error Handling

The library provides a comprehensive exception hierarchy for clear error handling:

- `ConfigurationError`: Raised when there are issues with initialization or configuration
- `ProviderError`: Raised for provider-related issues (validation, lookup, etc.)
- `TokenError`: Raised for token validation and verification issues
- `StorageError`: Raised for storage-related issues (PKCE, JWKS, etc.)
- `AuthenticationError`: Raised for general authentication failures

Example error handling:

```python
from authutils.common.exceptions import (
    ConfigurationError,
    ProviderError,
    TokenError,
    StorageError,
    AuthenticationError
)

try:
    # Your authentication code here
    pass
except TokenError as e:
    # Handle token validation errors
    print(f"Token validation failed: {e}")
except ProviderError as e:
    # Handle provider-related errors
    print(f"Provider error: {e}")
except StorageError as e:
    # Handle storage-related errors
    print(f"Storage error: {e}")
except ConfigurationError as e:
    # Handle configuration errors
    print(f"Configuration error: {e}")
except AuthenticationError as e:
    # Handle general authentication errors
    print(f"Authentication failed: {e}")
```

## Quick Start

### Basic Setup

```python
from authutils import BackendAuthProviderRegistry, GoogleAuthProvider
from authutils import LocalPKCEStorage, LocalJWKSStorage
from authutils import create_fastapi_auth_dependency

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
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from authutils import create_fastapi_auth_dependency, create_fastapi_websocket_authenticator

app = FastAPI()

# Create dependencies
auth_dependency = create_fastapi_auth_dependency(registry)
websocket_auth = create_fastapi_websocket_authenticator(registry)

# Protected REST endpoint
@app.get("/api/protected")
async def protected_route(user_claims: dict = Depends(auth_dependency)):
    return {"message": f"Hello, {user_claims['sub']}!"}

# Protected WebSocket endpoint
@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    user_claims: dict = Depends(websocket_auth)
):
    await websocket.accept()
    # Handle WebSocket communication
```

## Core Components

### Provider Registry

The `BackendAuthProviderRegistry` is the central component that manages authentication providers and handles token operations:

```python
registry = BackendAuthProviderRegistry(
    pkce_storage=LocalPKCEStorage(),
    jwks_storage=LocalJWKSStorage()
)
```

### Authentication Flow

The library provides two main authentication flows:

1. **Authorization Code Flow with PKCE**:
   ```python
   from authutils import initiate_auth_flow, process_token_exchange
   
   # Start the auth flow
   auth_url, state, code_verifier = await initiate_auth_flow(
       registry=registry,
       provider=ProviderTypeEnum.GOOGLE,
       redirect_uri="your-redirect-uri"
   )
   
   # Process the callback
   tokens = await process_token_exchange(
       registry=registry,
       code="authorization-code",
       state=state,
       code_verifier=code_verifier,
       redirect_uri="your-redirect-uri"
   )
   ```

2. **Token Verification**:
   ```python
   from authutils import verify_id_token
   
   # Verify an ID token
   claims = await verify_id_token(
       id_token="your-id-token",
       auth_provider=provider,
       jwks_storage=storage
   )
   ```

### Storage Backends

The library provides flexible storage backends for PKCE and JWKS:

```python
from authutils import LocalPKCEStorage, LocalJWKSStorage

# Local in-memory storage
pkce_storage = LocalPKCEStorage()
jwks_storage = LocalJWKSStorage()

# Custom storage implementations can be created by implementing
# the base storage interfaces
```

## Framework Integrations

### FastAPI

The library provides comprehensive FastAPI integration:

1. **REST API Authentication**:
   ```python
   from authutils import create_fastapi_auth_dependency
   
   auth_dependency = create_fastapi_auth_dependency(registry)
   
   @app.get("/api/protected")
   async def protected_route(user_claims: dict = Depends(auth_dependency)):
       return {"message": f"Hello, {user_claims['sub']}!"}
   ```

2. **WebSocket Authentication**:
   ```python
   from authutils import create_fastapi_websocket_authenticator
   
   websocket_auth = create_fastapi_websocket_authenticator(registry)
   
   @app.websocket("/ws")
   async def websocket_endpoint(
       websocket: WebSocket,
       user_claims: dict = Depends(websocket_auth)
   ):
       await websocket.accept()
       # Handle WebSocket communication
   ```

## Contributing

Contributions are welcome! Areas for contribution include:
- New authentication providers
- Additional storage backends
- Framework integrations
- Documentation improvements

## License

MIT License 