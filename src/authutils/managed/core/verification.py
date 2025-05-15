# managed/core/verification.py
# This file contains the core logic for verifying ID tokens.

import logging
from typing import Dict, Any, Optional
from jose import jwt, JOSEError
import httpx
import time

# Configure logging for this module
logger = logging.getLogger(__name__)

from ...common.exceptions import (
    TokenError,
    ConfigurationError,
    AuthenticationError
)
from ..providers.base import BackendAuthProvider
from ..storage.base import JWKSStorage

# --- Core Token Verification Function ---
# This function performs the actual JWT validation (signature, claims, expiration, etc.)
async def verify_id_token(
    id_token: str,
    auth_provider: BackendAuthProvider, # The service instance for the token's issuer
    jwks_storage: JWKSStorage,       # The JWKS storage instance
    access_token: Optional[str] = None # Make access_token optional
) -> Dict[str, Any]:
    """
    Verifies an ID token's signature and claims.

    Fetches JWKS using the provided storage, and validates the token against
    the expected issuer, audience, and expiration. Conditionally validates
    at_hash claim if access_token is provided.

    Args:
        id_token: The ID token string to verify.
        auth_provider: The BackendAuthProvider instance corresponding to the token's issuer.
        jwks_storage: The JWKS storage instance to fetch keys.
        access_token: The access token issued alongside the ID token (optional).
                      Required for at_hash validation if the ID token contains it.

    Returns:
        The decoded and validated token payload (claims) as a dictionary.

    Raises:
        TokenError: If verification fails (e.g., invalid signature, expired,
                    wrong issuer/audience, or at_hash mismatch if validated).
        ConfigurationError: If core components or storage were not initialized,
                      or for unexpected backend errors during JWKS fetching.
        AuthenticationError: For other unexpected errors.
    """
    logger.debug("Verification: Starting ID token verification.")

    # Check if core components are available
    if auth_provider is None or jwks_storage is None:
         logger.critical("Verification Error: Core managed auth components failed to load.")
         raise ConfigurationError("Backend authentication service is not fully configured.")

    # 1. Get the JWKS for the provider from storage (which handles fetching/caching)
    try:
        jwks = await jwks_storage.get_jwks(auth_provider)
        logger.debug("Verification: Retrieved JWKS.")
    except ValueError as e:
        logger.error(f"Verification Error: Failed to get JWKS for {auth_provider.get_name()}: {e}")
        raise ConfigurationError(f"Backend error getting JWKS for {auth_provider.get_name()}.") from e
    except Exception as e:
         logger.error(f"Verification Unexpected Error: Getting JWKS for {auth_provider.get_name()}: {e}", exc_info=True)
         raise ConfigurationError(f"An unexpected error occurred while getting JWKS for {auth_provider.get_name()}.") from e


    # 2. Get expected claims from the auth service configuration
    try:
        expected_issuer = auth_provider.get_issuer_url()
        expected_audience = auth_provider.get_client_id() # Audience is your client ID

        if not expected_issuer or not expected_audience:
             logger.critical(f"Verification Error: Backend configuration missing issuer or client ID for service: {auth_provider.get_name()}")
             raise ConfigurationError(f"Backend configuration error for service '{auth_provider.get_name()}': Missing verification details.")

        logger.debug(f"Verification: Expected Issuer: {expected_issuer}, Audience: {expected_audience}")

    except Exception as e:
        logger.error(f"Verification Error: Getting verification details from service {auth_provider.get_name()}: {e}", exc_info=True)
        raise ConfigurationError(f"Backend error getting verification details for {auth_provider.get_name()}.") from e


    # --- Prepare options for JOSE JWT decoding and validation ---
    # These options tell the jwt.decode function what to validate.
    options = {
        "verify_signature": True,       # Always verify the signature
        "verify_iss": True,             # Verify the issuer claim
        "verify_aud": True,             # Verify the audience claim
        "verify_exp": True,             # Verify the expiration time
        "verify_nbf": False,            # Don't verify 'not before' claim by default (optional)
        "verify_iat": False,            # Don't verify 'issued at' claim by default (optional)
        "verify_at_hash": False,        # <-- IMPORTANT: Set this to False by default
        "leeway": 10,                   # Allow a small clock skew (in seconds)
    }

    # --- Conditionally enable at_hash validation if access_token is provided ---
    if access_token is not None:
        # If an access token is provided, enable at_hash validation.
        # The jwt.decode function will then require the access_token argument.
        options["verify_at_hash"] = True
        logger.debug("Verification: access_token provided, enabling at_hash validation.")
    else:
         logger.debug("Verification: access_token not provided, skipping at_hash validation.")


    # --- Perform the JWT decoding and validation ---
    try:
        # Pass the ID token, JWKS, expected claims, and options to jwt.decode
        # Conditionally pass the access_token if it's not None
        decoded_token = jwt.decode(
            id_token,
            jwks, # The JWKS dictionary
            algorithms=["RS256"], # Specify expected algorithms (Google uses RS256)
            issuer=expected_issuer,
            audience=expected_audience,
            options=options, # Pass the configured options
            access_token=access_token # Pass access_token only if provided (matches options["verify_at_hash"])
        )
        logger.debug("Verification: ID token successfully decoded and validated.")
        return decoded_token # Return the validated claims payload

    except JOSEError as e:
        # Catch specific JOSE errors during decoding or validation
        logger.warning(f"Verification Error: Token validation failed: {e}")
        # Convert JOSE errors to a standard TokenError for the caller to handle
        raise TokenError(f"Token validation failed: {e}") from e

    except Exception as e:
         # Catch any other unexpected errors during the decoding/validation process
         logger.error(f"Verification Unexpected Error: Decoding/validation process: {e}", exc_info=True)
         raise AuthenticationError("An unexpected error occurred during token validation.") from e

# You might add other verification-related utilities here, e.g.,
# def extract_standardized_claims(token_payload: Dict[str, Any], auth_provider: BackendAuthProvider) -> Dict[str, Any]:
#     """
#     Uses the auth provider's extract_user_claims method to standardize claims.
#     """
#     return auth_provider.extract_user_claims(token_payload)