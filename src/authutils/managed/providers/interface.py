import abc
from ..types import AuthProviderEnum
class AuthProvider(abc.ABC):
    """
    Abstract Base Class (Interface) for backend authentication services.
    Defines the contract for services handling token exchange.
    """

    @abc.abstractmethod
    def get_type(self) -> AuthProviderEnum:
        """
        Get the unique type of the auth provider (e.g., 'google', 'github').
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

    # You could add other methods here if needed, e.g.,
    # @abc.abstractmethod
    # def get_user_info_url(self) -> str:
    #     """
    #     Get the user info endpoint URL (if needed for post-token exchange).
    #     """
    #     pass