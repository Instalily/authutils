import abc
from ...common.types.constants import ProviderTypeEnum
from typing import List

class BackendAuthProvider(abc.ABC):
    """
    Abstract Base Class (Interface) for backend authentication providers.
    Defines the contract for providers handling token exchange.
    """
    @abc.abstractmethod
    def get_name(self) -> ProviderTypeEnum:
        """
        Get the unique name of the auth provider (e.g., 'google', 'github') as an enum.
        """
        pass

    @abc.abstractmethod
    def get_client_id(self) -> str:
        """
        Get the client ID for this provider.
        """
        pass

    @abc.abstractmethod
    def get_client_secret(self) -> str:
        """
        Get the client secret for this provider.
        """
        pass

    @abc.abstractmethod
    def get_token_url(self) -> str:
        """
        Get the token exchange URL for this provider.
        """
        pass

    @abc.abstractmethod
    def get_issuer_url(self) -> str:
        """
        Get the issuer URL for this provider.
        """
        pass

    @abc.abstractmethod
    def get_jwks_url(self) -> str:
        """
        Get the JWKS URL for this provider.
        """
        pass

    @abc.abstractmethod
    def get_userinfo_url(self) -> str:
        """
        Get the user info endpoint URL for this provider.
        """
        pass

    @abc.abstractmethod
    def get_scopes(self) -> List[str]:
        """
        Get the scopes for this provider.
        """
        pass

    @abc.abstractmethod
    def build_auth_url(self, redirect_uri: str, state: str, code_challenge: str, code_challenge_method: str) -> str:
        """
        Build the auth URL for this provider.
        """
        pass

    # You could add other methods here if needed, e.g.,
    # @abc.abstractmethod
    # def get_user_info_url(self) -> str:
    #     """
    #     Get the user info endpoint URL (if needed for post-token exchange).
    #     """
    #     pass