# managed/core/exchange.py
# This file contains the core logic for exchanging authorization codes or
# refresh tokens with an identity provider's token endpoint.

import httpx
import logging
from typing import Dict, Any

# Configure logging for this module
logger = logging.getLogger(__name__)

from ...common.exceptions import (
    ProviderError,
    TokenError,
    ConfigurationError
)
from ..providers.base import BackendAuthProvider
from ..models.types import (
    AccessTokenRequestInternal,
    RefreshTokenRequestInternal,
    TokenResponse,
    ProviderErrorResponse
)


# --- Helper function to make the HTTP POST request to the token endpoint ---
# This extracts the common HTTP request logic to reduce duplication.
async def _post_to_token_endpoint(token_url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Makes an asynchronous POST request to the identity provider's token endpoint.

    Args:
        token_url: The URL of the token endpoint.
        params: The parameters to send in the request body (form-urlencoded).

    Returns:
        The JSON response dictionary from the provider.

    Raises:
        ProviderError: If the identity provider returns an error response.
        TokenError: If there's an error with token operations.
        ConfigurationError: For unexpected errors during the process.
    """
    async with httpx.AsyncClient() as client:
        try:
            logger.debug(f"Exchange: Sending POST request to {token_url} with params: {params}")
            # Use data= for form-urlencoded data, which token endpoints expect
            provider_response = await client.post(token_url, data=params)

            # Raise an exception for bad status codes (4xx or 5xx)
            provider_response.raise_for_status()

            # Parse the JSON response from the identity provider
            response_data = provider_response.json()
            logger.debug("Exchange: Successfully received response from provider.")
            # logger.debug(f"Exchange: Received response data: {response_data}") # Avoid logging sensitive data

            return response_data # Return the raw JSON data

        except httpx.HTTPStatusError as e:
            # Handle errors returned by the identity provider (4xx or 5xx status codes)
            logger.warning(f"Exchange HTTP error with provider: {e}")
            logger.debug(f"Exchange Debug: Provider response body: {e.response.text}")

            # Attempt to parse error response from provider if available
            if ProviderErrorResponse is not None:
                try:
                    # Try to parse the error response into the ProviderErrorResponse model
                    error_data = e.response.json()
                    provider_error = ProviderErrorResponse(**error_data)
                    # Extract common OAuth error fields from the validated model
                    detail = provider_error.error_description or provider_error.error or "Unknown provider error"
                    logger.warning(f"Exchange Provider error details: {detail}")
                    # Re-raise as ProviderError including details for the caller
                    raise ProviderError(f"Provider error: {detail}") from e
                except Exception:
                     # If provider response is not JSON or cannot be parsed into error model
                     logger.warning("Exchange: Could not parse provider error response as JSON or validate against error model.")
                     # Include part of the raw response text in the error detail
                     raw_detail = e.response.text[:200] + "..." if len(e.response.text) > 200 else e.response.text
                     raise ProviderError(f"Provider returned an error: {raw_detail}") from e # Re-raise including raw detail
            else:
                 # If ProviderErrorResponse model failed to import
                 logger.warning("Exchange: ProviderErrorResponse model not available for parsing error.")
                 raw_detail = e.response.text[:200] + "..." if len(e.response.text) > 200 else e.response.text
                 raise ProviderError(f"Provider returned an error: {raw_detail}") from e # Re-raise

        except httpx.RequestError as e:
            # Handle network errors or other request failures (e.g., provider endpoint is down)
            logger.error(f"Exchange Request error with provider: {e}", exc_info=True)
            raise TokenError(f"Network error communicating with provider: {e}") from e # Re-raise

        except Exception as e:
            # Catch any other unexpected errors during the request process
            logger.error(f"Exchange Unexpected error during HTTP request: {e}", exc_info=True)
            raise ConfigurationError(f"An internal error occurred during HTTP communication: {e}") from e # Re-raise as ConfigurationError


# --- Function for Authorization Code Exchange ---
async def exchange_authorization_code(
    token_request: AccessTokenRequestInternal, # Accepts only AccessTokenRequest
    auth_provider: BackendAuthProvider
) -> TokenResponse: # Returns TokenResponse
    """
    Exchanges an authorization code and PKCE verifier for tokens
    with the identity provider's token endpoint.

    Args:
        token_request: An AccessTokenRequest model instance.
        auth_provider: The BackendAuthProvider instance for the provider.

    Returns:
        A TokenResponse model instance containing the tokens.

    Raises:
        ProviderError: If the provider returns an error.
        TokenError: If there's an error with token operations.
        ConfigurationError: For backend configuration or unexpected errors.
    """
    if auth_provider is None or not isinstance(token_request, AccessTokenRequestInternal):
         logger.error("Exchange Error: Invalid input to exchange_authorization_code.")
         raise ConfigurationError("Backend error: Invalid input to exchange function.")

    logger.info(f"Exchange: Exchanging authorization code for provider: {auth_provider.get_name().value}")

    # Get provider configuration details
    client_id = auth_provider.get_client_id()
    client_secret = auth_provider.get_client_secret()
    token_url = auth_provider.get_token_url()

    if not client_id or not client_secret or not token_url:
         logger.error(f"Exchange Error: Missing configuration for service {auth_provider.get_name().value}")
         raise ConfigurationError(f"Backend configuration error for service {auth_provider.get_name().value}: Missing client ID, secret, or token URL.")

    # Construct parameters for the POST request to the provider
    # Fields are accessed directly from the AccessTokenRequest model
    token_exchange_params = {
        "grant_type": "authorization_code",
        "code": token_request.code,
        "redirect_uri": token_request.redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "code_verifier": token_request.code_verifier,
    }
    logger.debug("Exchange: Constructed parameters for authorization_code grant.")

    # --- Make the HTTP request using the helper function ---
    try:
        tokens_data = await _post_to_token_endpoint(token_url, token_exchange_params)

        # --- Parse the response data into the TokenResponse model ---
        # This validates the structure and types of the received tokens.
        if TokenResponse is not None:
            token_response_model = TokenResponse(**tokens_data)
            logger.info("Exchange: Successfully parsed provider response into TokenResponse model.")
            return token_response_model # Return the validated TokenResponse model
        else:
            logger.critical("Exchange Error: TokenResponse model not available.")
            raise ConfigurationError("Backend error: Token response model not loaded.")

    except ProviderError as e:
        raise e

    except TokenError as e:
        raise e

    except Exception as e:
        # Catch any other unexpected errors during the process (e.g., issues with model parsing)
        logger.error(f"Exchange Unexpected error during authorization code exchange: {e}", exc_info=True)
        raise ConfigurationError(f"An internal error occurred during authorization code exchange: {e}") from e


# --- Function for Refresh Token Exchange ---
async def exchange_refresh_token(
    token_request: RefreshTokenRequestInternal, # Accepts only RefreshTokenRequest
    auth_provider: BackendAuthProvider
) -> TokenResponse: # Returns TokenResponse
    """
    Exchanges a refresh token for new tokens with the identity provider's
    token endpoint.

    Args:
        token_request: A RefreshTokenRequest model instance.
        auth_provider: The BackendAuthProvider instance for the provider.

    Returns:
        A TokenResponse model instance containing the new tokens.

    Raises:
        ProviderError: If the provider returns an error.
        TokenError: If there's an error with token operations.
        ConfigurationError: For backend configuration or unexpected errors.
    """
    if auth_provider is None or not isinstance(token_request, RefreshTokenRequestInternal):
         logger.error("Exchange Error: Invalid input to exchange_refresh_token.")
         raise ConfigurationError("Backend error: Invalid input to exchange function.")

    logger.info(f"Exchange: Exchanging refresh token for provider: {auth_provider.get_name().value}")

    # Get provider configuration details
    client_id = auth_provider.get_client_id()
    client_secret = auth_provider.get_client_secret()
    token_url = auth_provider.get_token_url()

    if not client_id or not client_secret or not token_url:
         logger.error(f"Exchange Error: Missing configuration for service {auth_provider.get_name().value}")
         raise ConfigurationError(f"Backend configuration error for service {auth_provider.get_name().value}: Missing client ID, secret, or token URL.")

    # Construct parameters for the POST request to the provider
    # Fields are accessed directly from the RefreshTokenRequest model
    token_exchange_params = {
        "grant_type": "refresh_token",
        "refresh_token": token_request.refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
        # redirect_uri is generally NOT required for refresh token requests
        # If a provider *does* require it for refresh, you might need to add
        # it to the RefreshTokenRequest model and include it here.
        # "redirect_uri": auth_provider.get_redirect_uri(), # Example if needed
    }
    logger.debug("Exchange: Constructed parameters for refresh_token grant.")

    # --- Make the HTTP request using the helper function ---
    try:
        tokens_data = await _post_to_token_endpoint(token_url, token_exchange_params)

        # --- Parse the response data into the TokenResponse model ---
        # This validates the structure and types of the received tokens.
        if TokenResponse is not None:
            token_response_model = TokenResponse(**tokens_data)
            logger.info("Exchange: Successfully parsed provider response into TokenResponse model.")
            return token_response_model # Return the validated TokenResponse model
        else:
            logger.critical("Exchange Error: TokenResponse model not available.")
            raise ConfigurationError("Backend error: Token response model not loaded.")

    except ProviderError as e:
        raise e

    except TokenError as e:
        raise e

    except Exception as e:
        # Catch any other unexpected errors during the process (e.g., issues with model parsing)
        logger.error(f"Exchange Unexpected error during refresh token exchange: {e}", exc_info=True)
        raise ConfigurationError(f"An internal error occurred during refresh token exchange: {e}") from e


# --- Remove the original exchange_code_for_tokens function ---
# async def exchange_code_for_tokens(...): # REMOVED
#    pass


# --- Needed Imports ---
# import httpx # Ensure httpx is imported
# import logging # Ensure logging is imported
# from typing import Dict, Any, Union # Ensure Dict, Any, Union are imported
# from .models import AccessTokenRequest, RefreshTokenRequest, TokenResponse, ProviderErrorResponse # Ensure models are imported
# from .providers.interface import BackendAuthProvider # Ensure BackendAuthProvider is imported