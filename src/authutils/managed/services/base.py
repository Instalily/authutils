import abc
from ..models import AuthServiceEnum
from typing import Dict, Any, List

class BackendAuthService(abc.ABC):
    """
    Abstract Base Class (Interface) for backend authentication services.
    Defines the contract for services handling token exchange.
    """
    @abc.abstractmethod
    def get_name(self) -> AuthServiceEnum:
        """
        Get the unique name of the auth service (e.g., 'google', 'github') as an enum.
        """
        pass

    @abc.abstractmethod
    def get_client_id(self) -> str:
        """
        Get the client ID for this service.
        """
        pass

    @abc.abstractmethod
    def get_client_secret(self) -> str:
        """
        Get the client secret for this service.
        """
        pass

    @abc.abstractmethod
    def get_token_url(self) -> str:
        """
        Get the token exchange URL for this service.
        """
        pass

    @abc.abstractmethod
    def get_issuer_url(self) -> str:
        """
        Get the issuer URL for this service.
        """
        pass

    @abc.abstractmethod
    def get_jwks_url(self) -> str:
        """
        Get the JWKS URL for this service.
        """
        pass

    @abc.abstractmethod
    def get_user_info_url(self) -> str:
        """
        Get the user info endpoint URL for this service.
        """
        pass

    @abc.abstractmethod
    def get_scopes(self) -> List[str]:
        """
        Get the scopes for this service.
        """
        pass

    @abc.abstractmethod
    def build_auth_url(self, redirect_uri: str) -> str:
        """
        Build the auth URL for this service.
        """
        pass

    # You could add other methods here if needed, e.g.,
    # @abc.abstractmethod
    # def get_user_info_url(self) -> str:
    #     """
    #     Get the user info endpoint URL (if needed for post-token exchange).
    #     """
    #     pass