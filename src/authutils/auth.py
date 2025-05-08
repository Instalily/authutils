import secrets
import jwt
from datetime import datetime, timedelta, timezone

class AuthConfig:
    def __init__(self, secret_key: str | None = None, algorithm: str = "HS256"):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = algorithm

    def __repr__(self):
        return f"AuthConfig(algorithm='{self.algorithm}', secret_key='***')"

def generate_token(user_id: str, info: dict, auth_config: AuthConfig, expires_in_minutes: int = 60) -> str:
    '''
    Generates a JWT token for the given user ID and info.

    Args:
        user_id (str): The ID of the user to generate a token for.
        info (dict): The info to include in the token.
        app (Flask): The Flask application instance.
        expires_in_minutes (int): The number of minutes the token will be valid for.
    '''
    payload = {
        "user_id": user_id,
        "info": info,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
    }
    return jwt.encode(payload, auth_config.secret_key, algorithm=auth_config.algorithm)

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
        payload = jwt.decode(token, auth_config.secret_key, algorithms=[auth_config.algorithm])
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None
    
def validate_token_claims(payload: dict, expected_info: dict[str, list[str]]) -> tuple[bool, str | None]:
    """
    Validates that each expected claim is present in the JWT payload and matches an allowed value.
    Returns a tuple (True, None) if valid, or (False, reason) if invalid.
    """
    info = payload.get("info", {})
    for key, allowed_values in expected_info.items():
        if key not in info:
            return False, f"Missing required claim: {key}"
        if info[key] not in allowed_values:
            return False, f"Claim '{key}' not allowed: {info[key]}"
    return True, None