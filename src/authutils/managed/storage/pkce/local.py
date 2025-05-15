# managed/storage/pkce/local.py
from .base import PKCEStorage # Assuming this defines the abstract methods
import time # Still needed for potential timestamp usage elsewhere, but not directly by TTLCache TTL
from ....common.types.constants import ProviderTypeEnum
from typing import Dict, Any, Tuple # Import necessary types
import cachetools # Import the cachetools library
from ....common.exceptions import StorageError

# Define the default TTL for PKCE state in seconds (e.g., 5 minutes)
# PKCE verifiers should be short-lived for security.
DEFAULT_PKCE_TTL_SECONDS = 5 * 60 # 5 minutes

class LocalPKCEStorage(PKCEStorage):
    """
    In-memory PKCE state storage implementation using cachetools.TTLCache.

    This provides thread-safe storage with automatic expiration based on TTL.
    NOTE: Data is lost when the application restarts. Not suitable for
    multi-instance deployments without a shared cache backend like Redis.
    """
    def __init__(self, ttl_seconds: int = DEFAULT_PKCE_TTL_SECONDS):
        # Use TTLCache for thread-safe in-memory storage with Time-To-Live
        # maxsize: Maximum number of items in the cache (choose an appropriate size)
        # ttl: Time-To-Live for each item in seconds
        self._auth_requests: cachetools.TTLCache = cachetools.TTLCache(
            maxsize=1000, # Example: allow up to 1000 pending auth requests in memory
            ttl=ttl_seconds # Expiration time for each state entry in seconds
        )
        # Store the TTL for potential future reference or logging
        self._ttl_seconds = ttl_seconds
        print(f"Initialized LocalPKCEAuthStorage with TTL: {ttl_seconds} seconds")

    # Assuming the base class method is synchronous (adjust if async)
    def store(self, state: str, code_verifier: str, provider: ProviderTypeEnum):
        """
        Stores the PKCE code verifier and provider name associated with a state.
        Uses the state as the cache key. Automatically handled by TTLCache TTL.

        Args:
            state: The state parameter from the auth flow
            code_verifier: The PKCE code verifier
            provider: The authentication provider

        Raises:
            StorageError: If storage operation fails
        """
        # The data to store for this state
        details_to_store = {
            'code_verifier': code_verifier,
            'provider': provider,
            # TTLCache handles the timestamp internally based on the 'ttl' parameter
            # 'timestamp': time.time() # Not needed when using TTLCache TTL
        }

        try:
            # Store the details in the TTLCache, keyed by the state string.
            # If state already exists, it will be overwritten (and TTL reset).
            # TTLCache is thread-safe for item assignment.
            self._auth_requests[state] = details_to_store
            print(f"Stored auth request for state (first 10 chars): {state[:10]}...")
        except Exception as e:
             # Handle potential errors during storage (less likely with TTLCache unless maxsize is hit)
             print(f"Error storing auth request for state {state[:10]}...: {e}")
             raise StorageError(f"Failed to store PKCE details for state {state[:10]}...: {e}")

    # Assuming the base class method is synchronous (adjust if async)
    # Return type hint matches the tuple format expected by the caller
    # Assuming the base class expects (code_verifier, provider_name)
    def retrieve_and_clear(self, state: str) -> Tuple[str, ProviderTypeEnum] | None:
        """
        Retrieves and removes the stored details for a state.
        Returns (code_verifier, provider_name) tuple or None if not found or expired.
        TTLCache automatically handles expiration checks in a thread-safe manner.

        Args:
            state: The state parameter from the auth flow

        Returns:
            Tuple of (code_verifier, provider) or None if not found/expired

        Raises:
            StorageError: If retrieval operation fails
        """
        if not state:
            return None

        try:
            # Use cachetools.TTLCache.pop() to retrieve and remove the item atomically.
            # This is thread-safe and handles expired items automatically.
            # If the state is not in the cache or has expired, pop(state, None) returns the default (None).
            details = self._auth_requests.pop(state, None)

            if details:
                print(f"Retrieved and cleared auth request for state (first 10 chars): {state[:10]}...")

                # Extract the stored details from the retrieved dictionary
                code_verifier = details.get('code_verifier')
                provider = details.get('provider') # This should be the BackendAuthProvider member

                # Basic check to ensure required details are present in the retrieved data
                if code_verifier is None or provider is None:
                     print(f"Error: Retrieved details for state {state[:10]}... are incomplete.")
                     raise StorageError(f"Retrieved PKCE details for state {state[:10]}... are incomplete")

                # Return the details as a tuple (matching the expected return type)
                # Assuming the base class expects (code_verifier, auth_provider)
                return (code_verifier, provider) # Return the tuple

            else:
                # State not found in cache or was already expired and removed by TTLCache
                print(f"No auth request details found or state expired for state: {state[:10]}...")
                return None

        except Exception as e:
            # Catch any unexpected errors during retrieval/pop from the cache
            print(f"An unexpected error occurred during retrieval for state {state[:10]}...: {e}")
            raise StorageError(f"Failed to retrieve PKCE details for state {state[:10]}...: {e}")

# --- Needed Imports ---
# from typing import Dict, Any, Tuple # Ensure these are imported
# import time # Still needed for potential timestamp usage elsewhere, but not directly by TTLCache TTL
# from ...models import AuthServiceEnum # Ensure this is imported
# from .base import PKCEAuthStorage # Ensure base is imported
# import cachetools # Ensure cachetools is imported
