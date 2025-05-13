from .models import AccessTokenRequest, RefreshTokenRequest
from .services import AuthService
from typing import Dict
import httpx

async def exchange_authorization_code_for_tokens(
    access_token_request: AccessTokenRequest,
    auth_service: AuthService
) -> Dict:
    """
    Exchanges an authorization code and PKCE verifier for tokens with the identity provider.
    """
    print(f"Registry: Exchanging auth code for provider: {access_token_request.service}")

    client_id = auth_service.get_client_id()
    client_secret = auth_service.get_client_secret()
    token_url = auth_service.get_token_url()

    # Construct the parameters for the POST request to the provider
    token_exchange_params = {
        "grant_type": "authorization_code",
        "code": access_token_request.code,
        "redirect_uri": access_token_request.redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "code_verifier": access_token_request.code_verifier,
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
    refresh_token_request: RefreshTokenRequest,
    auth_service: AuthService
) -> Dict:
    """
    Exchanges a refresh token for new ID and access tokens with the identity provider.
    """
    print(f"Registry: Exchanging refresh token for provider: {refresh_token_request.service}")

    client_id = auth_service.get_client_id()
    client_secret = auth_service.get_client_secret()
    token_url = auth_service.get_token_url()


    # Construct the parameters for the POST request to the provider
    refresh_params = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token_request.refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": refresh_token_request.redirect_uri,
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