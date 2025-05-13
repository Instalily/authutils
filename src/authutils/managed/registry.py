from typing import Dict
import httpx
from .providers.interface import AuthProvider # Import the interface
from .providers.google import GoogleAuthProvider # Import concrete services
from .types.token_request import TokenRequest, AuthProviderEnum

class AuthProviderRegistry:
    """
    Registry for backend authentication providers.
    Provides access to provider configurations by name.
    """
    def __init__(self):
        self._providers: Dict[AuthProviderEnum, AuthProvider] = {}

    def register_provider(self, provider: AuthProvider):
        """
        Register a backend auth provider.
        """
        if not isinstance(provider, AuthProvider):
            print(f"Warning: Registered object is not an instance of AuthProvider: {provider}")
            raise TypeError("Registered provider must be an instance of AuthProvider")

        self._providers[provider.get_type()] = provider
        print(f"Registered backend auth provider: {provider.get_type()}")

    def get_provider(self, name: str) -> AuthProvider:
        """
        Get a registered backend auth provider by name.
        """
        provider = self._providers.get(name)
        if not provider:
            raise ValueError(f"Backend auth provider '{name}' not found in registry.")
        return provider

    def has_service(self, name: str) -> bool:
        """
        Check if a provider is registered.
        """
        return name in self._providers

    def get_all_providers(self) -> list[AuthProvider]:
        """
        Get all registered backend auth providers.
        """
        return list(self._providers.values())
    
    async def exchange_authorization_code_for_tokens(
        self,
        token_request: TokenRequest
    ) -> Dict:
        """
        Exchanges an authorization code and PKCE verifier for tokens with the identity provider.
        """
        print(f"Registry: Exchanging auth code for provider: {token_request.provider_name}")

        try:
            auth_provider = self.get_provider(token_request.provider)
        except ValueError as e:
            print(f"Registry Error: {e}")
            raise ValueError(f"Unsupported provider for code exchange: {token_request.provider}") from e # Re-raise as ValueError

        client_id = auth_provider.get_client_id()
        client_secret = auth_provider.get_client_secret()
        token_url = auth_provider.get_token_url()

        # Construct the parameters for the POST request to the provider
        token_exchange_params = {
            "grant_type": "authorization_code",
            "code": token_request.code,
            "redirect_uri": token_request.redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "code_verifier": token_request.code_verifier,
        }

        async with httpx.AsyncClient() as client:
            try:
                print(f"Registry: Sending token exchange request to {token_url}...")
                provider_response = await client.post(token_url, data=token_exchange_params)
                provider_response.raise_for_status() # Raise for bad status codes

                tokens = provider_response.json()
                print("Registry: Successfully exchanged code for tokens with provider.")
                return tokens # Return the tokens dictionary

            except httpx.HTTPStatusError as e:
                print(f"Registry HTTP error during token exchange with provider: {e}")
                print(f"Registry Response body: {e.response.text}")
                # Re-raise with original error details for the endpoint to handle
                raise ValueError(f"Provider error during code exchange: {e.response.status_code} - {e.response.text}") from e
            except httpx.RequestError as e:
                print(f"Registry Request error during token exchange with provider: {e}")
                raise ValueError(f"Network error communicating with provider: {e}") from e
            except Exception as e:
                print(f"Registry Unexpected error during code exchange: {e}")
                raise ValueError(f"An unexpected error occurred during code exchange: {e}") from e
            
    async def exchange_refresh_token(
        self,
        token_request: TokenRequest
    ) -> Dict:
        """
        Exchanges a refresh token for new ID and access tokens with the identity provider.
        """
        print(f"Registry: Exchanging refresh token for provider: {token_request.provider_name}")

        try:
            auth_provider = self.get_provider(token_request.provider_name)
        except ValueError as e:
            print(f"Registry Error: {e}")
            raise ValueError(f"Unsupported provider for refresh: {token_request.provider_name}") from e # Re-raise as ValueError

        client_id = auth_provider.get_client_id()
        client_secret = auth_provider.get_client_secret()
        token_url = auth_provider.get_token_url()

        if not token_request.refresh_token:
            raise ValueError("Refresh token is required for token refresh.")

        # Construct the parameters for the POST request to the provider
        refresh_params = {
            "grant_type": "refresh_token",
            "refresh_token": token_request.refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": token_request.redirect_uri,
        }

        async with httpx.AsyncClient() as client:
            try:
                print(f"Registry: Sending refresh token request to {token_url}...")
                provider_response = await client.post(token_url, data=refresh_params)
                provider_response.raise_for_status() # Raise for bad status codes

                tokens = provider_response.json()
                print("Registry: Successfully refreshed tokens with provider.")
                return tokens # Return the tokens dictionary

            except httpx.HTTPStatusError as e:
                print(f"Registry HTTP error during token refresh with provider: {e}")
                print(f"Registry Response body: {e.response.text}")
                raise ValueError(f"Provider error during refresh: {e.response.status_code} - {e.response.text}") from e
            except httpx.RequestError as e:
                print(f"Registry Request error during token refresh with provider: {e}")
                raise ValueError(f"Network error communicating with provider during refresh: {e}") from e
            except Exception as e:
                print(f"Registry Unexpected error during token refresh: {e}")
                raise ValueError(f"An unexpected error occurred during token refresh: {e}") from e