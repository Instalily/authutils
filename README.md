# AuthUtils

A modular authentication library that provides easy token-based authentication and info-based access control. Currently supports Flask with plans to add support for FastAPI and other frameworks.

## Features

- Modular design with framework-agnostic core
- JWT-based authentication
- Flexible info-based access control
- Framework-specific adapters (Flask support included)
- Easy integration with existing applications

## Installation

```bash
pip install authutils
```

## Quick Start

### Core Usage (Framework Agnostic)

```python
from authutils import AuthConfig, generate_token, verify_token, require_info

# Create auth configuration
auth_config = AuthConfig(
    secret_key="your-secret-key",  # Optional, will generate one if not provided
    algorithm="HS256"  # Optional, defaults to HS256
)

# Generate a token
token = generate_token(
    user_id="user123",
    info={
        "role": "admin",
        "permissions": ["read", "write"],
        "department": "engineering"
    },
    auth_config=auth_config
)

# Verify a token
payload = verify_token(token, auth_config)
if payload:
    user_id = payload["user_id"]
    info = payload["info"]

# Use the require_info decorator
@require_info({"role": ["admin"]})
def protected_function(payload, *args, **kwargs):
    return f"Hello {payload['user_id']}!"
```

### Flask Integration

```python
from flask import Flask
from authutils import init_flask_auth, flask_require_info

app = Flask(__name__)

# Initialize Flask integration
auth_config = init_flask_auth(app)

@app.route('/login', methods=['POST'])
def login():
    # Your authentication logic here
    user_id = "user123"
    user_info = {
        "role": "admin",
        "permissions": ["read", "write"],
        "department": "engineering"
    }
    
    # Generate token
    token = generate_token(
        user_id=user_id,
        info=user_info,
        auth_config=auth_config
    )
    
    return {"token": token}

@app.route('/admin')
@flask_require_info({"role": ["admin"]})
def admin_route(payload, *args, **kwargs):
    return {"message": f"Hello {payload['user_id']}!"}

@app.route('/engineering')
@flask_require_info({
    "role": ["admin", "engineer"],
    "department": ["engineering"]
})
def engineering_route(payload, *args, **kwargs):
    return {"message": "Engineering department only"}
```

## Documentation

### Core Components

The library is designed with a modular architecture:

1. **Core Authentication (`auth.py`)**
   - `AuthConfig`: Configuration class for authentication settings
   - `generate_token`: Create JWT tokens with custom info
   - `verify_token`: Verify token validity
   - `validate_token_claims`: Validate token info against requirements

2. **Access Control (`decorators.py`)**
   - `require_info`: Framework-agnostic decorator for access control
   - Validates token info against expected values

3. **Framework Adapters**
   - `flask_adapter.py`: Flask-specific integration
   - More adapters planned for FastAPI and other frameworks

### Configuration

The `AuthConfig` class provides flexible configuration options:

```python
config = AuthConfig(
    secret_key="your-secret-key",  # Optional
    algorithm="HS256"  # Optional
)
```

### Token Management

Generate tokens with custom info:
```python
token = generate_token(
    user_id="user123",
    info={
        "role": "admin",
        "permissions": ["read", "write"]
    },
    auth_config=auth_config
)
```

Verify tokens:
```python
payload = verify_token(token, auth_config)
if payload:
    user_id = payload["user_id"]
    info = payload["info"]
```

### Access Control

The `require_info` decorator provides flexible access control:

```python
# Simple role check
@require_info({"role": ["admin"]})
def admin_function(payload, *args, **kwargs):
    pass

# Multiple conditions
@require_info({
    "role": ["admin", "manager"],
    "permissions": ["write"]
})
def management_function(payload, *args, **kwargs):
    pass
```

### Flask Integration

The Flask adapter provides seamless integration:

```python
# Use decorator
@app.route('/protected')
@flask_require_info({"role": ["admin"]}, auth_config)
def protected_route(payload, *args, **kwargs):
    return {"message": "Protected route"}
```

### Future Framework Support

Planned framework integrations:
- FastAPI
- Django
- More to come...

## Contributing

Contributions are welcome! Areas for contribution include:
- New framework adapters
- Additional authentication methods
- Enhanced token validation
- Documentation improvements

## License

MIT License 