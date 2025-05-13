# AuthUtils

A modular authentication library that provides easy token-based authentication and info-based access control. Supports both manual token management and managed authentication with various providers.

## Features

- Modular design with framework-agnostic core
- JWT-based authentication
- Flexible info-based access control with a single decorator
- Managed authentication with provider support (Google, more coming soon)
- Manual token management for custom implementations
- Easy integration with existing applications

## Installation

```bash
pip install authutils
```

## Quick Start

### Manual Token Management

```python
from authutils.manual.token_utils import AuthConfig, generate_token, verify_token

# Create auth configuration
auth_config = AuthConfig(
    provider_name="your-app",  # Required: identifies your application
    secret_key="your-secret-key",  # Optional, will generate one if not provided
    algorithm="HS256"  # Optional, defaults to HS256
)

# Generate a token
payload = {
    "user_id": "user123",  # Example field, can be any custom info
    "role": "admin",
    "permissions": ["read", "write"],
    "department": "engineering"
}

token = generate_token(payload, auth_config, expires_in_minutes=60)  # Optional expiration

# Verify a token
verified_payload = verify_token(token, auth_config)
if verified_payload:
    # Access any fields from payload as needed
    if "user_id" in verified_payload:
        user_id = verified_payload["user_id"]
```

### Managed Authentication

```python
from authutils.managed import AuthProviderRegistry
from authutils.managed.providers import GoogleAuthProvider
from authutils.managed.types import TokenRequest, AuthProviderEnum

# Initialize the provider registry
registry = AuthProviderRegistry()

# Register Google provider
google_provider = GoogleAuthProvider(
    client_id="your-client-id",
    client_secret="your-client-secret"
)
registry.register_provider(google_provider)

# Exchange authorization code for tokens
token_request = TokenRequest(
    code="authorization-code",
    code_verifier="pkce-verifier",
    redirect_uri="your-redirect-uri",
    provider=AuthProviderEnum.GOOGLE
)

# Exchange code for tokens
tokens = await registry.exchange_authorization_code_for_tokens(token_request)

# Refresh tokens
refresh_request = TokenRequest(
    code="",  # Not needed for refresh
    code_verifier="",  # Not needed for refresh
    redirect_uri="your-redirect-uri",
    provider=AuthProviderEnum.GOOGLE,
    refresh_token="your-refresh-token"
)
new_tokens = await registry.exchange_refresh_token(refresh_request)
```

## Documentation

### Core Components

The library is designed with a modular architecture:

1. **Manual Token Management (`manual/token_utils.py`)**
   - `AuthConfig`: Configuration class for authentication settings
   - `generate_token`: Create JWT tokens from a payload dictionary
   - `verify_token`: Verify token validity

2. **Managed Authentication (`managed/`)**
   - `AuthProviderRegistry`: Central registry for managing authentication providers
   - Provider implementations (Google, more coming soon)
   - Token exchange and refresh functionality

### Configuration

The `AuthConfig` class provides flexible configuration options:

```python
config = AuthConfig(
    provider_name="your-app",  # Required: identifies your application
    secret_key="your-secret-key",  # Optional
    algorithm="HS256"  # Optional
)
```

### Token Management

Generate tokens with a payload dictionary:
```python
# The payload can contain any custom fields you need
payload = {
    "user_id": "user123",
    "role": "admin",
    "permissions": ["read", "write"],
    "custom_field": "custom_value"
}

# Generate token with default expiration (60 minutes)
token = generate_token(payload, auth_config)

# Or specify custom expiration in minutes
token = generate_token(payload, auth_config, expires_in_minutes=120)  # 2 hour expiration
```

Note: The following fields in the payload are reserved and will be automatically managed:
- `iat` (Issued At): Automatically set to the current timestamp
- `exp` (Expiration): Automatically set based on `expires_in_minutes` (defaults to 60 minutes)
- `iss` (Issuer): Automatically set to the provider_name from AuthConfig

### Managed Authentication

The managed authentication system provides a flexible way to integrate with various authentication providers:

```python
# Initialize registry
registry = AuthProviderRegistry()

# Register providers
google_provider = GoogleAuthProvider(
    client_id="your-client-id",
    client_secret="your-client-secret"
)
registry.register_provider(google_provider)

# Exchange authorization code
token_request = TokenRequest(
    code="authorization-code",
    code_verifier="pkce-verifier",
    redirect_uri="your-redirect-uri",
    provider=AuthProviderEnum.GOOGLE
)
tokens = await registry.exchange_authorization_code_for_tokens(token_request)

# Refresh tokens
refresh_request = TokenRequest(
    code="",
    code_verifier="",
    redirect_uri="your-redirect-uri",
    provider=AuthProviderEnum.GOOGLE,
    refresh_token="your-refresh-token"
)
new_tokens = await registry.exchange_refresh_token(refresh_request)
```

### Provider Support

Currently supported providers:
- Google OAuth2

Planned provider support:
- GitHub
- Microsoft
- More to come...

## Contributing

Contributions are welcome! Areas for contribution include:
- New authentication providers
- Additional token validation features
- Documentation improvements

## License

MIT License 