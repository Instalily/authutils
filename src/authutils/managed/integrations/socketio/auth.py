# managed/integrations/socketio/auth.py
# This file contains a utility for authenticating Socket.IO connections.

import logging
from typing import Dict, Any, Optional, Callable # Import Callable for type hinting
import socketio # Import socketio for ConnectionRefusedError
from jose import jwt, JOSEError # For getting unverified claims

# Configure logging for this module
logger = logging.getLogger(__name__)

from ...core.verification import verify_id_token
from ...providers.base import BackendAuthProvider
from ...storage.jwks.base import JWKSStorage
from ...registry import BackendAuthProviderRegistry

# --- Socket.IO Authentication Decorator/Utility Factory ---
# This factory function takes the initialized registry and returns
# an async function suitable for use with @sio.on('connect').
def create_socketio_authenticator(
    registry: BackendAuthProviderRegistry # Accept the initialized registry instance
) -> Callable[[str, Dict[str, Any], Optional[Dict[str, Any]]], Optional[Dict[str, Any]]]: # <-- Updated return type hint for 3 args
    """
    Factory function to create a Socket.IO 'connect' event handler
    that authenticates the connection using a token from the 'auth' payload.

    Args:
        registry: The initialized BackendAuthProviderRegistry instance.

    Returns:
        An async function (connect handler) that takes sid, environ, and auth payload.
        This function handles authentication and raises ConnectionRefusedError
        on failure, or returns user claims on success.
    """
    # Check if core components were imported successfully and registry is valid
    if registry is None or verify_id_token is None: # Add check for verify_id_token if it might fail import
         logger.critical("Socket.IO authenticator factory cannot create handler: Core managed auth components failed to load or registry is None.")
         # Return a handler function that always refuses the connection with an error
         async def failed_authenticator(sid: str, environ: Dict[str, Any], auth: Optional[Dict[str, Any]] = None): # Match target signature
             logger.critical(f"Attempted to use an uninitialized Socket.IO authenticator for sid: {sid}.")
             raise ConnectionRefusedError('Backend authentication service is not configured.') # Refuse connection
         return failed_authenticator


    # --- The actual Socket.IO Connect Handler (Inner Function) ---
    # This async function is created by the factory and has access to the 'registry'
    # from the outer scope (closure).
    async def authenticated_connect_handler(
        sid: str,
        environ: Dict[str, Any],
        auth: Optional[Dict[str, Any]] = None # <--- ADD THE AUTH PARAMETER HERE (make it optional)
    ) -> Optional[Dict[str, Any]]:
        """
        Socket.IO 'connect' event handler that authenticates the client.

        Expects the ID token in the 'auth' payload of the connection request.
        If authentication fails, raises ConnectionRefusedError.
        If authentication succeeds, returns the user claims.

        Args:
            sid: The session ID of the connecting client.
            environ: The WSGI/ASGI environment dictionary for the connection.
            auth: The authentication payload sent by the client (if any).

        Returns:
            The decoded and validated token payload (claims) as a dictionary if
            authentication is successful.

        Raises:
            ConnectionRefusedError: If authentication fails.
        """
        logger.info(f"Socket.IO Auth Handler: Attempting to authenticate connection for sid: {sid}.")
        # Optional debug logs for the raw inputs
        # logger.debug(f"Socket.IO Auth Handler: Environ for sid {sid}: {environ}")
        logger.debug(f"Socket.IO Auth Handler: Auth payload for sid {sid}: {auth}")


        # --- 1. Get the token directly from the 'auth' parameter ---
        # This parameter is now passed directly to this handler function.
        id_token = auth.get('token') if auth and isinstance(auth, dict) else None
        logger.debug(f"Socket.IO Auth Handler: Extracted token from auth: {id_token[:10]}..." if id_token else "Socket.IO Auth Handler: No token found in auth payload.")


        if not id_token:
            logger.warning(f"Socket.IO Auth Handler: Client {sid} connection attempt missing auth token in payload.")
            # Refuse the connection with a specific reason
            raise ConnectionRefusedError('Authentication token missing.') # Refuse connection

        # --- 2. Verify the token ---
        try:
            # Get the unverified claims to find the issuer ('iss')
            try:
                unverified_claims = jwt.get_unverified_claims(id_token) # Requires 'jose' library
                issuer_url = unverified_claims.get("iss")
                if not issuer_url:
                     logger.warning(f"Socket.IO Auth Handler: Token from client {sid} missing 'iss' claim.")
                     raise ConnectionRefusedError('Invalid token: Missing issuer.') # Refuse connection
            except JOSEError as e:
                 logger.warning(f"Socket.IO Auth Handler: Failed to get unverified claims from token for sid {sid}: {e}")
                 raise ConnectionRefusedError('Malformed token.') # Refuse connection


            # Find the corresponding auth service in the registry based on the issuer URL
            try:
                 # --- Use the 'registry' from the outer scope (factory) ---
                 auth_provider: BackendAuthProvider = registry.find_provider_by_issuer(issuer_url)
                 logger.debug(f"Socket.IO Auth Handler: Found provider '{auth_provider.get_name().value}' for issuer '{issuer_url}' for sid {sid}.")
            except ValueError as e: # find_service_by_issuer raises ValueError if not found
                 logger.warning(f"Socket.IO Auth Handler: No registered service found for issuer: {issuer_url} for sid {sid}: {e}")
                 raise ConnectionRefusedError('Unknown token issuer.') # Refuse connection
            except Exception as e:
                 logger.error(f"Socket.IO Auth Handler: Unexpected error finding service by issuer '{issuer_url}' for sid {sid}: {e}", exc_info=True)
                 raise ConnectionRefusedError('Backend error finding authentication service.') # Refuse connection


            # Get the JWKS storage instance from the registry
            try:
                # --- Use the 'registry' from the outer scope (factory) ---
                jwks_storage_instance: JWKSStorage = registry.get_jwks_storage()
                logger.debug(f"Socket.IO Auth Handler: Accessed JWKS storage instance from registry for sid {sid}.")
            except Exception as e:
                logger.critical(f"Socket.IO Auth Handler: Getting JWKS storage from registry for sid {sid}: {e}", exc_info=True)
                raise ConnectionRefusedError('Backend configuration error: Cannot access JWKS storage.') # Refuse connection


            # Call the core verification function
            # Pass the id_token obtained directly from the 'auth' parameter
            authenticated_user_claims: Dict[str, Any] = await verify_id_token(
                id_token=id_token, # <--- Use the id_token extracted from the auth param
                auth_provider=auth_provider, # Pass the provider instance
                jwks_storage=jwks_storage_instance, # Pass the storage instance
                # access_token is None by default in verify_id_token, so at_hash is skipped
            )

            logger.info(f"Socket.IO Auth Handler: Authentication successful for sid {sid}, user: {authenticated_user_claims.get('sub', 'N/A')}")

            # --- Return the validated claims if successful ---
            # The caller (the actual @sio.on('connect') handler in main.py) will receive this
            # and can store it in the session.
            return authenticated_user_claims

        except (ValueError, RuntimeError) as e:
            # Catch verification errors (ValueError) or backend errors (RuntimeError) from verify_id_token
            logger.warning(f"Socket.IO Auth Handler: Authentication failed during token verification for sid {sid}: {e}")
            # Raise ConnectionRefusedError to refuse the connection
            raise ConnectionRefusedError(f'Authentication failed: {e}') # Refuse connection

        except Exception as e:
            # Catch any other unexpected errors during the handshake or verification process
            logger.error(f"Socket.IO Auth Handler Unexpected Error for sid {sid}: {e}", exc_info=True)
            raise ConnectionRefusedError('Internal server error during authentication.') # Refuse connection

    # Return the inner connect handler function
    return authenticated_connect_handler