# managed/providers/google.py
from typing import Dict, Any, List
from urllib.parse import urlencode # Helper for building query strings
from .base import BackendAuthProvider # Import the base provider class
from ...common.types.constants import ProviderTypeEnum # Import the AuthServiceEnum
from ...common.exceptions import ConfigurationError

class GoogleAuthProvider(BackendAuthProvider):
    """
    Backend authentication provider implementation for Google.
    Handles configuration and URL building for Google OAuth 2.0 / OpenID Connect.
    """
    def __init__(self, client_id: str, client_secret: str):
        # In a real app, load these securely from environment variables
        # or a secrets manager.
        if not client_id or not client_secret:
             raise ConfigurationError("Google Client ID and Secret must be provided.")
        self._client_id = client_id
        self._client_secret = client_secret

    def get_name(self) -> ProviderTypeEnum:
        """
        Get the unique name (ProviderTypeEnum member) of the auth provider.
        """
        return ProviderTypeEnum.GOOGLE

    def get_client_id(self) -> str:
        """
        Get the client ID for this service.
        """
        return self._client_id

    def get_client_secret(self) -> str:
        """
        Get the client secret for this service.
        """
        return self._client_secret

    def get_authorization_base_url(self) -> str:
        """
        Get the base authorization endpoint URL for Google.
        """
        return 'https://accounts.google.com/o/oauth2/v2/auth'

    def get_token_url(self) -> str:
        """
        Get the token exchange URL for Google.
        """
        return 'https://oauth2.googleapis.com/token'

    def get_issuer_url(self) -> str:
        """
        Get the issuer URL (iss claim) for Google.
        """
        return "https://accounts.google.com"

    def get_jwks_url(self) -> str:
        """
        Get the JWKS URL for Google's public keys.
        """
        return "https://www.googleapis.com/oauth2/v3/certs"

    def get_scopes(self) -> List[str]:
        """
        Get the default scopes requested for Google OpenID Connect.
        """
        # These should match the scopes requested by your frontend
        return ['openid', 'email', 'profile']

    def get_additional_params(self) -> Dict[str, Any]:
        """
        Get default additional parameters for the authorization request.
        """
        # Google-specific parameters often used for web apps
        return {
            'access_type': 'offline', # Request a refresh token
            'prompt': 'consent' # Prompt the user for consent every time (can be 'select_account' or 'none')
        }
    
    def get_userinfo_url(self) -> str:
        """
        Get the user info endpoint URL for Google.
        """
        return "https://www.googleapis.com/oauth2/v3/userinfo"

    def build_auth_url(
        self,
        redirect_uri: str,
        state: str,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
        additional_params: Dict[str, Any] | None = None # Allow overriding/adding params
    ) -> str:
        """
        Build the complete authorization URL for Google, including PKCE parameters.
        """
        base_url = self.get_authorization_base_url()

        # Standard OAuth 2.0 / OIDC parameters
        params: Dict[str, Any] = {
            'client_id': self.get_client_id(),
            'redirect_uri': redirect_uri,
            'response_type': 'code', # Using Authorization Code flow
            'scope': ' '.join(self.get_scopes()), # Scopes joined by space
            'state': state, # Include the state parameter
            # Include default additional parameters
            **self.get_additional_params()
        }

        # Add PKCE parameters if provided
        if code_challenge and code_challenge_method:
            params['code_challenge'] = code_challenge
            params['code_challenge_method'] = code_challenge_method

        # Override or add any additional dynamic parameters passed in
        if additional_params:
            params.update(additional_params)

        # Build the query string
        query_string = urlencode(params)

        # Return the full URL
        return f"{base_url}?{query_string}"

