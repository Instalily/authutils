# managed/integrations/fastapi/dependencies.py
# This file contains FastAPI-specific dependencies for authentication.

from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt # Import jwt instead of get_unverified_claims
from typing import Dict, Any, Callable # Import Callable for type hinting the factory return type
import logging # Use logging
import traceback # For logging unexpected errors

# Configure logging for this module
logger = logging.getLogger(__name__)

from ...core.verification import verify_id_token
from ...providers.base import BackendAuthProvider
from ...storage.jwks.base import JWKSStorage
from ...registry import BackendAuthProviderRegistry
from ....common.exceptions import (
    ConfigurationError,
    ProviderError,
    TokenError,
    StorageError
)

# --- FastAPI Security Scheme ---
# Define an HTTPBearer scheme to extract the token from the Authorization header.
# auto_error=False prevents FastAPI from automatically returning a 401,
# allowing our dependency function to handle the error response manually.
bearer_scheme = HTTPBearer(auto_error=False)

# --- Dependency Factory Function ---
# This function takes the initialized registry and returns the actual dependency function.
def create_fastapi_auth_dependency(
    registry: BackendAuthProviderRegistry # Accept the initialized registry instance
) -> Callable[[HTTPAuthorizationCredentials | None], Dict[str, Any]]:
    """
    Factory function to create a FastAPI authentication dependency.

    Args:
        registry: The initialized BackendAuthProviderRegistry instance.

    Returns:
        An async dependency function that can be used with FastAPI's Depends().

    Raises:
        ConfigurationError: If core components failed to load or registry is invalid.
    """
    # Check if core components were imported successfully and registry is valid
    if registry is None or verify_id_token is None:
         logger.critical("Auth dependency factory cannot create dependency: Core managed auth components failed to load or registry is None.")
         raise ConfigurationError("Backend authentication service is not configured.")

    # --- The actual FastAPI Authentication Dependency (Inner Function) ---
    # This function is created by the factory and has access to the 'registry'
    # from the outer scope (closure).
    async def get_authenticated_user(
        credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme)
    ) -> Dict[str, Any]:
        """
        FastAPI dependency to extract and verify the ID token from the Authorization header.

        This dependency is used in protected endpoints. It extracts the token,
        finds the corresponding authentication service using the token's issuer,
        verifies the token's signature and claims using the JWKS storage,
        and returns the validated token payload (claims).

        Args:
            credentials: The Authorization header credentials provided by HTTPBearer.

        Returns:
            The decoded and validated token payload (claims) as a dictionary.

        Raises:
            HTTPException: 401 Unauthorized if the token is missing, invalid, or expired.
                           500 Internal Server Error for backend configuration or unexpected errors.
        """
        # 1. Check if credentials were provided by the HTTPBearer scheme
        if not credentials:
            # If no Authorization header or invalid format, return 401
            logger.info("Dependency: Authorization header missing or invalid format.")
            raise HTTPException(
                status_code=401,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"}, # Standard header for OAuth 2.0 Bearer tokens
            )

        # Extract the token string from the credentials object
        id_token = credentials.credentials # This is the token string (e.g., the ID token)

        # --- Use 'iss' claim to find the correct provider configuration for verification ---
        try:
            # 2. Get the unverified claims from the token to find the issuer ('iss').
            unverified_claims = jwt.get_unverified_claims(id_token)
            issuer = unverified_claims.get("iss")

            # Check if the 'iss' claim is present in the token
            if not issuer:
                 logger.warning("Dependency Error: Token missing 'iss' claim.")
                 raise TokenError("Invalid token: Missing issuer.")

            # 3. Use the registry (from the factory's scope) to find the corresponding backend service instance based on the issuer URL.
            try:
                 # Assuming find_provider_by_issuer returns a BackendAuthProvider instance
                 auth_provider: BackendAuthProvider = registry.find_provider_by_issuer(issuer) # <-- Use 'registry' from outer scope
                 logger.debug(f"Dependency: Found provider '{auth_provider.get_name().value}' for issuer '{issuer}'.")
            except ProviderError as e: # Catch ProviderError if find_provider_by_issuer raises it (e.g., issuer not mapped)
                 logger.warning(f"Dependency Error: Issuer '{issuer}' from token does not map to a known provider: {e}")
                 raise HTTPException(status_code=401, detail="Invalid token issuer.") from e # Chain exception
            except Exception as e:
                 logger.error(f"Dependency Error: Unexpected error finding provider by issuer '{issuer}': {e}", exc_info=True)
                 raise HTTPException(status_code=500, detail="Backend error finding authentication provider.") from e


            # 4. Get the JWKS storage instance from the registry (from the factory's scope).
            try:
                jwks_storage_instance: JWKSStorage = registry.get_jwks_storage() # <-- Use 'registry' from outer scope
                logger.debug("Dependency: Accessed JWKS storage instance from registry.")
            except StorageError as e:
                logger.critical(f"Dependency Error: Getting JWKS storage from registry: {e}", exc_info=True)
                # This indicates a backend configuration error, not a client token error.
                raise HTTPException(status_code=500, detail="Backend configuration error: Cannot access JWKS storage.") from e


        except Exception as e:
            # Catch any other unexpected errors while processing token claims or accessing registry/storage
            logger.error(f"Dependency Unexpected Error: Processing token claims or accessing registry/storage: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail="An internal error occurred during token processing.") from e


        # --- Verify the token signature and claims using the core verification function ---
        try:
            # 5. Call the core verification function from your 'managed.verification' module.
            # Pass the token string, the found auth service instance, and the JWKS storage instance.
            # This function handles fetching JWKS (via storage) and performing JWT decoding/validation.
            decoded_token = await verify_id_token( # verify_id_token is imported directly
                id_token=id_token,
                auth_provider=auth_provider, # Pass the provider instance
                jwks_storage=jwks_storage_instance # Pass the storage instance
            )
            # If verify_id_token completes without raising an exception, the token is valid.
            logger.debug(f"Dependency: Token successfully verified for user: {decoded_token.get('sub')}")

            # 6. Optional: Extract standardized user claims if needed by the dependency caller.
            # If your application expects a consistent user object regardless of provider,
            # you would call auth_provider.extract_user_claims(decoded_token) here.
            # standardized_claims = auth_provider.extract_user_claims(decoded_token)
            # return standardized_claims # Return the standardized claims

            # Return the raw decoded and validated token payload (claims)
            return decoded_token

        except TokenError as e:
            # Catch verification errors raised by verify_id_token (e.g., invalid signature, expired, wrong issuer/audience)
            logger.warning(f"Dependency Error: Token verification failed: {e}")
            # Convert the TokenError from the verification function into a 401 HTTPException
            raise HTTPException(status_code=401, detail=f"Invalid token: {e}") from e # Chain original exception

        except Exception as e:
             # Catch any other unexpected errors during the verification process (e.g., issues within verify_id_token after getting JWKS)
             logger.error(f"Dependency Unexpected Error: Token verification process: {e}", exc_info=True)
             raise HTTPException(status_code=500, detail="An internal error occurred during token verification.") from e

    # Return the inner dependency function
    return get_authenticated_user

# --- How to use this factory in main.py ---
# In your main.py, after initializing the registry:
# from managed.integrations.fastapi.dependencies import create_fastapi_auth_dependency
#
# # Assuming 'auth_registry' is your initialized BackendAuthProviderRegistry instance
# auth_dependency = create_fastapi_auth_dependency(auth_registry)
#
# Then, use the created dependency in your protected endpoints:
# @app.get("/api/protected")
# async def read_protected_data(user_claims: Dict[str, Any] = Depends(auth_dependency)): # Use the created dependency
#     # If this line is reached, user_claims contains the validated token payload
#     # ... endpoint logic ...
#     pass
