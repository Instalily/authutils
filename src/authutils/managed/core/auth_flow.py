# managed/core/auth_flow.py
# This file contains framework-agnostic utilities for initiating and handling
# the authentication flow (generating URLs, managing state) and processing
# token exchange/refresh requests.

import logging
from typing import Dict, Any, Union

# Configure logging for this module
logger = logging.getLogger(__name__)

from ...common.exceptions import (
    ProviderError,
    ConfigurationError,
    AuthenticationError
)
from ..registry import BackendAuthProviderRegistry
from ..models.types import ProviderTypeEnum, GrantTypeEnum, AccessTokenRequestInternal, RefreshTokenRequestInternal, TokenRequest
from ..utils.pkce import (
    generate_code_verifier,
    generate_code_challenge,
    generate_csrf_state,
)
from ..storage.base import PKCEStorage
from .exchange import exchange_authorization_code, exchange_refresh_token
from ...common.types.constants import GrantTypeEnum

# --- Utility Function to Initiate Authentication Flow ---
async def initiate_auth_flow(
    registry: BackendAuthProviderRegistry,
    provider_name_str: str, # The provider name as a string from the request
    redirect_uri: str
) -> str:
    """
    Initiates the authentication flow for a given provider.

    Generates PKCE parameters and state, stores them using the PKCE storage
    from the registry, and builds the authorization URL using the provider
    configuration from the registry.

    Args:
        registry: The initialized BackendAuthProviderRegistry instance.
        provider_name_str: The string name of the authentication provider (e.g., 'google').
        redirect_uri: The frontend callback URI where the provider should redirect.

    Returns:
        The complete authorization URL the frontend should redirect to.

    Raises:
        ProviderError: If the provider is unsupported or not found.
        ConfigurationError: If there's an issue with configuration or initialization.
        AuthenticationError: For unexpected errors during the process.
    """
    logger.info(f"Auth Flow: Initiating auth flow for provider: {provider_name_str}")

    # 1. Validate the requested provider name and get the provider instance from the registry
    try:
        # Convert the incoming string provider name to the ProviderTypeEnum
        # This will raise ValueError if the string doesn't match an Enum member
        provider_type = ProviderTypeEnum(provider_name_str)
        auth_provider = registry.get_provider(provider_type)
        logger.debug(f"Auth Flow: Retrieved provider '{provider_type.value}' from registry.")
    except ValueError as e: # Catches errors if provider string doesn't match Enum or provider not found
        logger.warning(f"Auth Flow Error: Unsupported provider requested: {provider_name_str}: {e}")
        raise ProviderError(f"Unsupported provider: {provider_name_str}") from e
    except Exception as e:
        logger.error(f"Auth Flow Error: Retrieving auth provider for {provider_name_str}: {e}", exc_info=True)
        raise ConfigurationError(f"Backend error configuring provider: {provider_name_str}") from e

    # 2. Generate PKCE parameters
    try:
        code_verifier = generate_code_verifier() # Use utility
        code_challenge = generate_code_challenge(code_verifier) # Use utility
        code_challenge_method = "S256" # Standard for PKCE
        logger.debug("Auth Flow: Generated PKCE parameters.")
    except Exception as e:
        logger.error(f"Auth Flow Error: Generating PKCE parameters for {provider_name_str}: {e}", exc_info=True)
        raise AuthenticationError("Backend error generating PKCE parameters.") from e

    # 3. Generate State parameter (including provider name and CSRF token)
    try:
        # Use the provider_name_str (string) for state generation as it's easier to parse later
        state, csrf_token = generate_csrf_state(provider_name_str) # Use utility
        logger.debug(f"Auth Flow: Generated state parameter: {state[:10]}...")
    except Exception as e:
        logger.error(f"Auth Flow Error: Generating state parameter for {provider_name_str}: {e}", exc_info=True)
        raise AuthenticationError("Backend error generating state parameter.") from e

    # 4. Store PKCE verifier and provider type using the PKCE storage instance from the registry
    try:
        # Get the PKCE storage instance from the registry
        pkce_storage_instance: PKCEStorage = registry.get_pkce_storage()
        # Use the storage instance's store method
        # Store the provider_type (Enum) with the verifier for type safety on retrieval
        pkce_storage_instance.store(state, code_verifier, provider_type)
        logger.debug(f"Auth Flow: Stored PKCE state for state (first 10 chars): {state[:10]}...")
    except Exception as e:
        logger.error(f"Auth Flow Error: Storing PKCE state for {provider_name_str}: {e}", exc_info=True)
        raise AuthenticationError("Backend error storing authentication state.") from e

    # 5. Call the provider's build_auth_url method
    try:
        # The provider builds the full URL using its base URL and the provided parameters
        # Assuming the provider implements build_auth_url and accepts the state parameter
        authorization_url = auth_provider.build_auth_url(
            redirect_uri=redirect_uri,
            state=state, # Pass the generated state
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method
            # additional_params=... # Pass any additional dynamic params if needed
        )
        logger.info(f"Auth Flow: Generated authorization URL for {provider_name_str}: {authorization_url[:100]}...")
    except Exception as e:
        logger.error(f"Auth Flow Error: Building authorization URL for {provider_name_str}: {e}", exc_info=True)
        raise ConfigurationError(f"Backend error building authorization URL for {provider_name_str}") from e

    # 6. Return the authorization URL
    return authorization_url


# --- Utility Function to Process Token Exchange/Refresh ---
# This function will be called by your /api/auth/token endpoint
# It encapsulates the logic previously in that endpoint.
async def process_token_exchange(
    registry: BackendAuthProviderRegistry,
    # --- Accept the single TokenRequest model as input ---
    request_body: TokenRequest
) -> Dict[str, Any]: # Return a dictionary for the endpoint
    """
    Processes the incoming token exchange or refresh request.

    Retrieves stored PKCE state if needed, gets the service from the registry,
    and calls the appropriate core exchange function (authorization code or refresh token).

    Args:
        registry: The initialized BackendAuthProviderRegistry instance.
        request_body: A Pydantic TokenRequest model instance containing the
                      request body data.

    Returns:
        A dictionary containing the tokens received from the identity provider.

    Raises:
        ProviderError: If the provider returns an error.
        ConfigurationError: If there's an issue with configuration or initialization.
        AuthenticationError: For unexpected errors during the process.
    """
    logger.info(f"Auth Flow: Processing token exchange request for grant type: {request_body.grant_type.value}")

    # Check if core components are available
    if registry is None or PKCEStorage is None or AccessTokenRequestInternal is None or RefreshTokenRequestInternal is None or exchange_authorization_code is None or exchange_refresh_token is None:
         logger.critical("Auth Flow Error: Core managed auth components or storage interface/exchange functions failed to load.")
         raise ConfigurationError("Backend authentication service is not fully configured.")

    # --- Access fields directly from the Pydantic model instance ---
    grant_type = request_body.grant_type
    provider_type = request_body.service # Use the ProviderTypeEnum directly from the model


    if grant_type == GrantTypeEnum.AUTHORIZATION_CODE: # Use the Enum member
        logger.debug(f"Auth Flow: Processing authorization_code grant for provider: {provider_type.value}")

        # 1. Access required fields directly from the model
        # Pydantic handles basic type validation and required fields if not Optional.
        # Custom validation in TokenRequest model ensures required fields are present.
        state = request_body.state
        code = request_body.code
        redirect_uri = request_body.redirect_uri
        # code_verifier is not in the Pydantic model received from frontend,
        # it's retrieved from storage using the state.

        # 2. Retrieve stored auth request details using the state from PKCE storage
        try:
            # Get the PKCE storage instance from the registry
            pkce_storage_instance: PKCEStorage = registry.get_pkce_storage()
            # Use the storage instance's retrieve_and_clear method
            # retrieve_and_clear returns (code_verifier, provider_name_enum) or None
            auth_details = pkce_storage_instance.retrieve_and_clear(state)
            if not auth_details:
                 # This could be a CSRF attack attempt, invalid state, or expired state
                 logger.warning(f"Auth Flow Warning: Invalid or expired state parameter received: {state[:10]}...")
                 raise AuthenticationError("Invalid or expired state parameter.")

            # Unpack the tuple returned by retrieve_and_clear
            stored_code_verifier, stored_provider_type_enum = auth_details

            # Optional but Recommended: Verify the provider type from the request body
            # matches the provider type stored with the state.
            if provider_type != stored_provider_type_enum: # Compare Enum members directly
                 logger.warning(f"Auth Flow Warning: Provider type mismatch. Request body: {provider_type.value}, Stored: {stored_provider_type_enum.value}")
                 # Decide how strict you want to be. Mismatch could indicate tampering.
                 # For security, you might want to raise a AuthenticationError here.
                 # raise AuthenticationError("Provider mismatch in request.")

        except AuthenticationError as e: # Catch AuthenticationErrors from storage (e.g., invalid state)
             raise e # Re-raise the AuthenticationError
        except Exception as e:
            logger.error(f"Auth Flow Error: Retrieving PKCE state for state {state[:10]}...: {e}", exc_info=True)
            raise AuthenticationError("Backend error retrieving authentication state.") from e


        # 3. Get the auth provider instance from the registry using the STORED provider type
        try:
            # Use the stored provider type (Enum) to get the provider from the registry
            auth_provider = registry.get_provider(stored_provider_type_enum)
            logger.debug(f"Auth Flow: Retrieved provider '{stored_provider_type_enum.value}' for authorization code exchange.")
        except ValueError as e: # Should not happen if stored type is valid
             logger.critical(f"Auth Flow Error: Stored provider type not found in registry: {stored_provider_type_enum.value}", exc_info=True)
             raise ConfigurationError(f"Backend configuration error: Stored provider '{stored_provider_type_enum.value}' not registered.") from e
        except Exception as e:
             logger.error(f"Auth Flow Error: Getting auth provider for stored type {stored_provider_type_enum.value}: {e}", exc_info=True)
             raise ConfigurationError(f"Backend error getting provider: {stored_provider_type_enum.value}") from e


        # 4. Prepare the request model for the core exchange function
        # Create an AccessTokenRequest model instance using data from the frontend and the stored verifier
        # This model is the specific input expected by exchange_authorization_code
        exchange_request_model = AccessTokenRequestInternal(
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=stored_code_verifier # <-- Use the STORED verifier
        )

        # 5. Call the core authorization code exchange function
        try:
           # Call the specific exchange_authorization_code function
           token_response_model = await exchange_authorization_code(
               token_request=exchange_request_model, # Pass the AccessTokenRequest model
               auth_provider=auth_provider # Pass the auth provider instance
           )
           logger.info("Auth Flow: Core authorization code exchange successful.")
           # Return the TokenResponse model converted back to a dictionary for the endpoint
           return token_response_model.model_dump() # Use model_dump() for Pydantic v2+

        except ProviderError as e: # Catch ProviderErrors from the exchange function
           logger.warning(f"Auth Flow Error: Core authorization code exchange failed: {e}")
           raise e # Re-raise the ProviderError

        except Exception as e: # Catch any other unexpected errors
            logger.error(f"Auth Flow Unexpected Error: Processing authorization code exchange: {e}", exc_info=True)
            raise AuthenticationError("An unexpected error occurred during authorization code exchange.") from e


    elif grant_type == GrantTypeEnum.REFRESH_TOKEN: # Use the Enum member
         logger.debug(f"Auth Flow: Processing refresh_token grant for provider: {provider_type.value}")

         # 1. Access required fields directly from the model
         # Pydantic handles basic type validation and required fields if not Optional.
         # Custom validation in TokenRequest model ensures required fields are present.
         refresh_token = request_body.refresh_token
         # provider_type is already accessed above

         # 2. Get the auth provider instance from the registry using the provider type from the request body
         # For refresh, we rely on the frontend telling us the provider type.
         try:
             # Use the provider type (Enum) directly from the model
             auth_provider = registry.get_provider(provider_type)
             logger.debug(f"Auth Flow: Retrieved provider '{provider_type.value}' for refresh.")
         except ValueError as e:
             logger.warning(f"Auth Flow Error: Unsupported provider requested for refresh: {provider_type.value}: {e}")
             raise ProviderError(f"Unsupported provider for refresh: {provider_type.value}") from e
         except Exception as e:
              logger.error(f"Auth Flow Error: Getting auth provider for refresh {provider_type.value}: {e}", exc_info=True)
              raise ConfigurationError(f"Backend error getting provider for refresh: {provider_type.value}") from e


         # 3. Prepare the request model for the core exchange function
         # Create a RefreshTokenRequest model instance using data from the frontend
         # This model is the specific input expected by exchange_refresh_token
         exchange_request_model = RefreshTokenRequestInternal(
             refresh_token=refresh_token
         )

         # 4. Call the core refresh token exchange function
         try:
            # Call the specific exchange_refresh_token function
            token_response_model = await exchange_refresh_token(
                token_request=exchange_request_model, # Pass the RefreshTokenRequest model
                auth_provider=auth_provider # Pass the auth provider instance
            )
            logger.info("Auth Flow: Core refresh token exchange successful.")
            # Return the TokenResponse model converted back to a dictionary for the endpoint
            return token_response_model.model_dump() # Use model_dump() for Pydantic v2+

         except ProviderError as e: # Catch ProviderErrors from the exchange function
            logger.warning(f"Auth Flow Error: Core refresh token exchange failed: {e}")
            raise e # Re-raise the ProviderError

         except Exception as e: # Catch any other unexpected errors
             logger.error(f"Auth Flow Unexpected Error: Processing refresh token exchange: {e}", exc_info=True)
             raise AuthenticationError("An unexpected error occurred during refresh token exchange.") from e


    else:
        # This case should not be reachable if the input is strictly TokenRequest
        # due to Pydantic validation based on the grant_type field, but included for robustness.
        logger.warning(f"Auth Flow Warning: Received unexpected grant type: {grant_type}")
        raise ProviderError(f"Unsupported grant_type: {grant_type}")