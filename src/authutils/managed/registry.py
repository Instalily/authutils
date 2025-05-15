# managed/registry.py
from typing import Dict, Type # Import Type for type hinting classes
# Import the storage interfaces (not concrete implementations)
from .storage.pkce.base import PKCEStorage
from .storage.jwks.base import JWKSStorage
# Import the service interface and concrete services (for registration)
from .providers import BackendAuthProvider
from ..common.types.constants import ProviderTypeEnum
from ..common.exceptions import (
    ConfigurationError,
    ProviderError,
    StorageError
)

# --- Backend Auth Service Registry ---
class BackendAuthProviderRegistry:
    """
    Registry for backend authentication providers.
    Manages provider instances and provides access by ProviderType or issuer.
    Accepts storage implementations via dependency injection.
    """
    def __init__(
        self,
        pkce_storage: PKCEStorage, # Accept PKCE storage instance
        jwks_storage: JWKSStorage,     # Accept JWKS storage instance
        # You might also accept other configurations here if needed
        # e.g., default_redirect_uri: str
    ):
        self._services: Dict[ProviderTypeEnum, BackendAuthProvider] = {}
        # Store a mapping from issuer URL (string) to ProviderType for quick lookup during verification
        self._issuer_to_provider_map: Dict[str, ProviderTypeEnum] = {}

        # Store the injected storage instances
        self._pkce_storage = pkce_storage
        self._jwks_storage = jwks_storage

        # You might store other configurations passed in here
        # self._default_redirect_uri = default_redirect_uri

        print("BackendAuthProviderRegistry initialized with storage instances.")


    def register_provider(self, provider: BackendAuthProvider):
        """
        Register a backend auth provider instance.
        Uses the provider's get_name() as the key.
        Maps the provider's issuer URL for lookup.

        Args:
            provider: The BackendAuthProvider instance to register.

        Raises:
            ProviderError: If the provider is invalid or already registered.
            ConfigurationError: If there's an issue with provider configuration.
        """
        if not isinstance(provider, BackendAuthProvider):
             print(f"Warning: Registered object is not an instance of BackendAuthProvider: {provider}")
             raise ProviderError("Registered provider must be an instance of BackendAuthProvider")

        provider_type = provider.get_name() # Get the ProviderType Enum member
        if not isinstance(provider_type, ProviderTypeEnum):
             print(f"Warning: Provider '{provider.get_name()}' get_name() did not return a ProviderTypeEnum Enum member.")
             raise ProviderError(f"Provider '{provider.get_name()}' get_name() must return a ProviderTypeEnum Enum member.")


        if provider_type in self._services:
            print(f"Warning: Provider '{provider_type.value}' already registered. Overwriting.")

        self._services[provider_type] = provider
        print(f"Registered backend auth provider: {provider_type.value}")

        # Add mapping from issuer to provider type
        try:    
            # Ensure the service implements get_issuer_url
            if not hasattr(provider, 'get_issuer_url') or not callable(provider.get_issuer_url):
                 print(f"Warning: Provider '{provider_type.value}' does not implement get_issuer_url(). Cannot map by issuer.")
            else:
                issuer = provider.get_issuer_url()
                if issuer in self._issuer_to_provider_map:
                     print(f"Warning: Issuer '{issuer}' already mapped to '{self._issuer_to_provider_map[issuer].value}'. Overwriting mapping to '{provider_type.value}'.")
                self._issuer_to_provider_map[issuer] = provider_type # Map issuer string to ProviderType Enum
                print(f"Mapped issuer '{issuer}' to provider '{provider_type.value}'")
        except Exception as e:
            print(f"Error mapping issuer for provider '{provider_type.value}': {e}")
            raise ConfigurationError(f"Failed to configure provider '{provider_type.value}': {e}")


    def get_provider(self, provider_type: ProviderTypeEnum) -> BackendAuthProvider:
        """
        Get a registered backend auth provider by its ProviderTypeEnum.

        Args:
            provider_type: The ProviderTypeEnum to look up.

        Returns:
            The registered BackendAuthProvider instance.

        Raises:
            ProviderError: If the provider type is invalid or not found.
        """
        if not isinstance(provider_type, ProviderTypeEnum):
             raise ProviderError("Provider type must be a ProviderTypeEnum Enum member.")

        provider = self._services.get(provider_type)
        if not provider:
            raise ProviderError(f"Backend auth provider '{provider_type.value}' not found in registry.")
        return provider

    def has_provider(self, provider_type: ProviderTypeEnum) -> bool:
        """
        Check if a provider is registered by its ProviderTypeEnum.

        Args:
            provider_type: The ProviderTypeEnum to check.

        Returns:
            True if the provider is registered, False otherwise.
        """
        if not isinstance(provider_type, ProviderTypeEnum):
             # Decide if this should raise an error or just return False
             print("Warning: has_provider called with non-ProviderTypeEnum argument.")
             return False
        return provider_type in self._services

    def get_all_providers(self) -> list[BackendAuthProvider]:
        """
        Get all registered backend auth provider instances.

        Returns:
            A list of all registered BackendAuthProvider instances.
        """
        return list(self._services.values())

    def find_provider_by_issuer(self, issuer: str) -> BackendAuthProvider:
        """
        Find a registered backend auth provider based on its issuer URL.
        Used during token verification.

        Args:
            issuer: The issuer URL to look up.

        Returns:
            The registered BackendAuthProvider instance.

        Raises:
            ProviderError: If the issuer is invalid or not found.
        """
        if not isinstance(issuer, str) or not issuer:
             raise ProviderError("Issuer must be a non-empty string.")

        # Look up ProviderType using the issuer URL
        provider_type = self._issuer_to_provider_map.get(issuer)
        if not provider_type:
             raise ProviderError(f"No registered service found for issuer '{issuer}'.")

        # Get the provider instance using the found provider type
        return self.get_provider(provider_type) # Reuse get_provider method

    # --- Provide access to the injected storage instances ---
    def get_pkce_storage(self) -> PKCEStorage:
        """
        Get the configured PKCE storage instance.

        Returns:
            The configured PKCEStorage instance.

        Raises:
            StorageError: If the storage was not initialized.
        """
        if self._pkce_storage is None: # Check if storage was initialized successfully
             raise StorageError("PKCE storage was not initialized.")
        return self._pkce_storage

    def get_jwks_storage(self) -> JWKSStorage:
        """
        Get the configured JWKS storage instance.

        Returns:
            The configured JWKSStorage instance.

        Raises:
            StorageError: If the storage was not initialized.
        """
        if self._jwks_storage is None: # Check if storage was initialized successfully
             raise StorageError("JWKS storage was not initialized.")
        return self._jwks_storage

    # You could add methods here for token exchange and verification,
    # but as discussed, it's generally better to put those in separate files
    # (e.g., exchange.py, verification.py) and have them use the registry
    # to get the necessary service configurations and storage instances.

    # Example placeholder methods (logic would be in exchange.py, verification.py)
    # async def exchange_authorization_code(self, code: str, code_verifier: str, redirect_uri: str, service_type: ProviderType) -> Dict:
    #     # This method would call the exchange logic from exchange.py
    #     pass
    #
    # async def verify_id_token(self, id_token: str) -> Dict:
    #      # This method would call the verification logic from verification.py
    #      pass

# --- Remove the automatic initialization of backend_service_registry here ---
# The registry instance will now be created and configured by the calling application code (e.g., main.py)
# and then passed to other parts of the application.
# backend_service_registry = BackendAuthServiceRegistry(...) # REMOVED