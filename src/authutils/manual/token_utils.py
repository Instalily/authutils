import secrets
import jwt
from datetime import datetime, timedelta, timezone

class AuthConfig:
    def __init__(self, provider_name: str, secret_key: str | None = None, algorithm: str = "HS256"):
        self.provider_name = provider_name
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = algorithm
        
    def __repr__(self):
        return f"AuthConfig(provider='{self.provider_name}', algorithm='{self.algorithm}', secret_key='***')"

def generate_token(payload: dict, auth_config: AuthConfig, expires_in_minutes: int = 60) -> str:
    '''
    Generates a JWT token for the given token payload.

    Args:
        token_payload (dict): The payload to include in the token.
    '''
    if "iat" in payload:
        raise ValueError("iat is reserved for internal use")
    
    if "exp" in payload:
        raise ValueError("exp is reserved for internal use")
    
    if "iss" in payload:
        raise ValueError("iss is reserved for internal use")

    token_payload = {
        "iss": auth_config.provider,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes),
        **payload,
    }
    return jwt.encode(token_payload, auth_config.secret_key, algorithm=auth_config.algorithm)

def verify_token(token: str, auth_config: AuthConfig):
    '''
    Verifies a JWT token and returns the payload if it is valid.

    Args:
        token (str): The JWT token to verify.
        app (Flask): The Flask application instance.

    Returns:
        dict: The payload of the token if it is valid, otherwise None.
    '''
    try:
        payload = jwt.decode(token, auth_config.secret_key, algorithms=[auth_config.algorithm], issuer=auth_config.provider_name)
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None