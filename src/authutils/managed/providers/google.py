# IMPORTANT: In a real application, load secrets from environment variables
# or a secrets manager, NOT hardcode them or load them directly from a file
# that might be committed to version control.
import os
from .interface import AuthProvider # Import the interface
from ..types import AuthProviderEnum
class GoogleAuthProvider(AuthProvider):
    """
    Backend authentication service implementation for Google.
    """
    def __init__(self, client_id: str, client_secret: str):
        # In a real app, you might load these from environment variables here
        # self.client_id = os.environ.get("GOOGLE_CLIENT_ID")
        # self.client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
        # if not self.client_id or not self.client_secret:
        #     raise ValueError("Google Client ID and Secret must be configured.")
        self.client_id = client_id # For demonstration, using constructor params
        self.client_secret = client_secret # For demonstration

    def get_type(self) -> AuthProviderEnum:
        return AuthProviderEnum.GOOGLE

    def get_client_id(self) -> str:
        return self.client_id

    def get_client_secret(self) -> str:
        return self.client_secret

    def get_token_url(self) -> str:
        return 'https://oauth2.googleapis.com/token'

    # Implement other methods from the interface if you added them
    # def get_user_info_url(self) -> str:
    #     return 'https://www.googleapis.com/oauth2/v3/userinfo'
