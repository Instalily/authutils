import secrets
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from typing import Optional

class AuthConfig:
    def __init__(self, provider_name: str, secret_key: str | None = None, algorithm: str = "HS256"):
        self.provider_name = provider_name
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.algorithm = algorithm
        
    def __repr__(self):
        return f"AuthConfig(provider='{self.provider_name}', algorithm='{self.algorithm}', secret_key='***')"

class JWTConfig:
    """
    Configuration for token generation and validation.
    
    Attributes:
        audience (str | None): The intended recipient of the token. If None, no audience validation is performed.
        not_before (datetime | None): Token is not valid before this time. If None, no not-before validation is performed.
        access_token (str | None): Associated access token for at_hash calculation. If None, no at_hash validation is performed.
        subject (str | None): The subject of the token. If None, no subject validation is performed.
        jwt_id (str | None): Unique identifier for the token. If None, no JWT ID validation is performed.
    """
    def __init__(
        self,
        audience: str | None = None,
        not_before: datetime | None = None,
        access_token: str | None = None,
        subject: str | None = None,
        jwt_id: str | None = None
    ):
        self.audience = audience
        self.not_before = not_before or datetime.now(timezone.utc)
        self.access_token = access_token
        self.subject = subject
        self.jwt_id = jwt_id

def generate_token(payload: dict, auth_config: AuthConfig, jwt_config: JWTConfig | None = None, expires_in_minutes: int = 60) -> str:
    '''
    Generates a JWT token for the given token payload.

    Args:
        payload (dict): The payload to include in the token.
        auth_config (AuthConfig): The authentication configuration.
        jwt_config (JWTConfig, optional): Additional token configuration including audience and access token.
        expires_in_minutes (int): Token expiration time in minutes. Defaults to 60.

    Returns:
        str: The generated JWT token.

    Raises:
        ValueError: If reserved claims (iat, exp, iss, aud, nbf, at_hash, sub, jti) are present in the payload.
        JWTError: If there is an error encoding the claims.
    '''
    reserved_claims = ["iat", "exp", "iss", "aud", "nbf", "at_hash", "sub", "jti"]
    for claim in reserved_claims:
        if claim in payload:
            raise ValueError(f"{claim} is reserved for internal use")

    claims = {
        "iss": auth_config.provider_name,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes),
        **payload,
    }

    # Add optional claims if jwt_config is provided
    if jwt_config:
        if jwt_config.audience is not None:
            claims["aud"] = jwt_config.audience
        if jwt_config.not_before is not None:
            claims["nbf"] = jwt_config.not_before
        if jwt_config.subject is not None:
            claims["sub"] = jwt_config.subject
        if jwt_config.jwt_id is not None:
            claims["jti"] = jwt_config.jwt_id

    # Extract access_token for at_hash calculation
    access_token = jwt_config.access_token if jwt_config and jwt_config.access_token is not None else None

    return jwt.encode(
        claims=claims,
        key=auth_config.secret_key,
        algorithm=auth_config.algorithm,
        headers=None,  # We don't need custom headers
        access_token=access_token
    )

def verify_token(token: str, auth_config: AuthConfig, jwt_config: JWTConfig | None = None):
    '''
    Verifies a JWT token and returns the payload if it is valid.

    Args:
        token (str): The JWT token to verify.
        auth_config (AuthConfig): The authentication configuration.
        jwt_config (JWTConfig, optional): Additional token configuration for validation.

    Returns:
        dict: The payload of the token if it is valid, otherwise None.

    Raises:
        JWTError: If the signature is invalid in any way.
        ExpiredSignatureError: If the signature has expired.
        JWTClaimsError: If any claim is invalid in any way.
    '''
    try:
        # Base options that are always enabled
        options = {
            'verify_signature': True,
            'verify_iat': True,
            'verify_exp': True,
            'verify_iss': True,
            'require_iat': True,
            'require_exp': True,
            'require_iss': True,
            'leeway': 0,
        }

        # Add validation for optional claims if token_config is provided
        if jwt_config:
            # Audience validation
            if jwt_config.audience is not None:
                options.update({
                    'verify_aud': True,
                    'require_aud': True,
                })
            else:
                options.update({
                    'verify_aud': False,
                    'require_aud': False,
                })

            # Not-before validation
            if jwt_config.not_before is not None:
                options.update({
                    'verify_nbf': True,
                    'require_nbf': True,
                })
            else:
                options.update({
                    'verify_nbf': False,
                    'require_nbf': False,
                })

            # Access token hash validation
            if jwt_config.access_token is not None:
                options.update({
                    'verify_at_hash': True,
                    'require_at_hash': True,
                })
            else:
                options.update({
                    'verify_at_hash': False,
                    'require_at_hash': False,
                })

            # Subject validation
            if jwt_config.subject is not None:
                options.update({
                    'verify_sub': True,
                    'require_sub': True,
                })
            else:
                options.update({
                    'verify_sub': False,
                    'require_sub': False,
                })

            # JWT ID validation
            if jwt_config.jwt_id is not None:
                options.update({
                    'verify_jti': True,
                    'require_jti': True,
                })
            else:
                options.update({
                    'verify_jti': False,
                    'require_jti': False,
                })
        else:
            # If no token_config, disable validation of optional claims
            options.update({
                'verify_aud': False,
                'require_aud': False,
                'verify_nbf': False,
                'require_nbf': False,
                'verify_at_hash': False,
                'require_at_hash': False,
                'verify_sub': False,
                'require_sub': False,
                'verify_jti': False,
                'require_jti': False,
            })

        # Extract parameters for jwt.decode
        audience = jwt_config.audience if jwt_config and jwt_config.audience is not None else None
        subject = jwt_config.subject if jwt_config and jwt_config.subject is not None else None
        access_token = jwt_config.access_token if jwt_config and jwt_config.access_token is not None else None

        return jwt.decode(
            token=token,
            key=auth_config.secret_key,
            algorithms=[auth_config.algorithm],
            audience=audience,
            issuer=auth_config.provider_name,
            subject=subject,
            access_token=access_token,
            options=options
        )
    except JWTError:
        return None