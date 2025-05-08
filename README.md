# Flask Auth

A Flask authentication addon that provides easy user authentication and role-based access control for your Flask applications.

## Features

- JWT-based authentication
- Role-based access control
- Flexible token types (access, refresh, or custom)
- Easy integration with existing Flask applications

## Installation

```bash
pip install flask-auth
```

## Quick Start

```python
from flask import Flask
from flask_auth import init_auth, require_role, generate_token, verify_token

app = Flask(__name__)

# Initialize the auth system
init_auth(app)

@app.route('/login', methods=['POST'])
def login():
    # Implement your own authentication logic here
    # For example, you might:
    # - Check credentials against a database
    # - Verify OAuth tokens
    # - Validate API keys
    # - etc.
    
    user_id = 1  # Get this from your authentication logic
    role = "admin"  # Get this from your authentication logic
    
    # Generate access token
    access_token = generate_token(
        user_id=user_id,
        role=role,
        token_type="access",
        app=app,
        expires_in_minutes=60
    )
    
    # Generate refresh token
    refresh_token = generate_token(
        user_id=user_id,
        role=role,
        token_type="refresh",
        app=app,
        expires_in_minutes=60 * 24 * 7  # 7 days
    )
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

@app.route('/refresh', methods=['POST'])
def refresh():
    refresh_token = request.json.get('refresh_token')
    if not refresh_token:
        return {"message": "Refresh token required"}, 400
        
    # Verify the refresh token
    payload = verify_token(refresh_token, app, expected_type="refresh")
    if not payload:
        return {"message": "Invalid refresh token"}, 401
    
    # Generate new access token
    new_access_token = generate_token(
        user_id=payload["user_id"],
        role=payload["role"],
        token_type="access",
        app=app
    )
        
    return {"access_token": new_access_token}

@app.route('/protected')
@require_role(["admin"])
def protected_route():
    return {"message": "This is a protected route"}
```

## Documentation

### Initialization

The package requires a Flask application and will automatically generate a secure secret key if one isn't provided:

```python
init_auth(app)
```

### Authentication

This package provides the token management and role-based access control, but leaves the actual authentication method up to you. You can implement any authentication method you prefer, such as:
- Password-based authentication
- OAuth
- API keys
- Social login
- Custom authentication methods

The only requirement is that your authentication logic must provide a `user_id` and `role` to generate the JWT tokens.

### Token Management

Generate tokens (access, refresh, or custom type):
```python
token = generate_token(
    user_id=user_id,
    role=role,
    token_type="access",  # or "refresh" or any custom type
    app=app,
    expires_in_minutes=60
)
```

Verify tokens:
```python
payload = verify_token(token, app, expected_type="access")
if payload:
    user_id = payload["user_id"]
    role = payload["role"]
```

### Authentication Decorators

The package provides a `@require_role` decorator that can be used to protect routes:

```python
@app.route('/admin')
@require_role(["admin"])
def admin_route():
    return {"message": "Admin only"}
```

### Configuration

The package automatically:
- Generates a secure `AUTH_SECRET_KEY` if one isn't provided

## License

MIT License 