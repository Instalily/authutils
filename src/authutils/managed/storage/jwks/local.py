# managed/storage/jwks/local.py
# Assuming base.py has been updated to define get_jwks as async def get_jwks(self, auth_provider: BackendAuthProvider)
from .base import JWKSStorage # Import the base abstract class
from ...providers import BackendAuthProvider # Import the BackendAuthProvider from providers.py
import time # Still useful for logging, but not for TTLCache expiration logic
from typing import Dict, Any # Import Dict and Any for type hints
import cachetools # Import the cachetools library
from ....common.exceptions import StorageError

# Define the default TTL for JWKS cache in seconds (e.g., 24 hours)
# Identity providers typically rotate keys infrequently, but check their docs.
DEFAULT_JWKS_TTL_SECONDS = 24 * 60 * 60 # 24 hours

class LocalJWKSStorage(JWKSStorage):
    """
    In-memory JWKS storage implementation using cachetools.TTLCache.

    Fetches and caches JSON Web Key Sets (JWKS) for authentication providers
    with a Time-To-Live (TTL). Provides thread-safe access.
    NOTE: Cache is lost when the application restarts.
    """
    def __init__(self, ttl_seconds: int = DEFAULT_JWKS_TTL_SECONDS):
        # Use TTLCache for thread-safe in-memory storage with Time-To-Live
        # maxsize: Maximum number of JWKS sets to cache (one per provider)
        # ttl: Expiration time for each JWKS set in seconds
        # The key for the cache will be the provider name (ProviderTypeEnum)
        self._jwks_cache: cachetools.TTLCache = cachetools.TTLCache(
            maxsize=10, # Example: cache JWKS for up to 10 different providers
            ttl=ttl_seconds # Expiration time for each JWKS set
        )
        self._ttl_seconds = ttl_seconds # Store the TTL for reference
        print(f"Initialized LocalJWKSStorage with TTL: {ttl_seconds} seconds")

    # This method signature MUST match the abstract method in base.py
    # Assuming base.py has been updated to 'async def get_jwks(self, auth_provider: BackendAuthProvider)'
    async def get_jwks(self, provider: BackendAuthProvider) -> Dict[str, Any]:
        """
        Gets JWKS for an auth provider from cache or by fetching, with TTL.

        Args:
            provider: The BackendAuthProvider instance for the provider.

        Returns:
            The JWKS dictionary.

        Raises:
            StorageError: If fetching or caching JWKS fails.
        """
        # Try to get JWKS from the cache.
        # TTLCache.get() automatically checks for expiration in a thread-safe way.
        # If the item is expired or not found, it returns the default (None).
        jwks = self._jwks_cache.get(provider)

        if jwks is None:
            # Cache miss or expired - need to fetch
            print(f"Cache miss or expired for JWKS for {provider.get_name()}. Fetching...")

            try:
                # Call the async fetch_jwks method from the base class, passing the provider instance
                # Await the async method call
                fetched_jwks = await self.fetch_jwks(provider)

                # Store the newly fetched JWKS in the cache.
                # TTLCache handles the timestamp and expiration based on the initialized ttl.
                # This operation is thread-safe.
                self._jwks_cache[provider] = fetched_jwks
                print(f"Successfully fetched and cached JWKS for {provider.get_name()}")

                return fetched_jwks # Return the newly fetched JWKS

            except Exception as e:
                # Catch any errors during the fetch process
                print(f"An error occurred while fetching JWKS for {provider.get_name()}: {e}")
                raise StorageError(f"Failed to get JWKS for {provider.get_name()}: {e}") from e

        else:
            # Cache hit - return the cached JWKS
            print(f"Using cached JWKS for {provider.get_name()}")
            return jwks

# --- Needed Imports ---
# from .base import JWKSStorage # Ensure this is imported
# from ...providers.interface import BackendAuthProvider # Ensure this is imported
# from ...models import AuthServiceEnum # Ensure this is imported
# import time # Still useful for logging, but not for TTLCache expiration logic
# from typing import Dict, Any # Ensure this is imported
# import cachetools # Ensure cachetools is imported
