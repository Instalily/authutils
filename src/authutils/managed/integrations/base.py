"""
Base interface for framework integrations.
"""

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict

from ...common.exceptions import ConfigurationError
from ..registry import BackendAuthProviderRegistry

class FrameworkIntegration(ABC):
    """Base interface for framework integrations."""
    
    @abstractmethod
    def create_auth_dependency(
        self,
        registry: BackendAuthProviderRegistry
    ) -> Callable[..., Dict[str, Any]]:
        """
        Create an authentication dependency for the framework.
        
        Args:
            registry: The authentication provider registry
            
        Returns:
            A dependency function that can be used with the framework
            
        Raises:
            ConfigurationError: If the integration cannot be configured
        """
        pass
    
    @abstractmethod
    def create_websocket_authenticator(
        self,
        registry: BackendAuthProviderRegistry
    ) -> Callable[..., Dict[str, Any]]:
        """
        Create a WebSocket authentication handler for the framework.
        
        Args:
            registry: The authentication provider registry
            
        Returns:
            A WebSocket authentication handler function
            
        Raises:
            ConfigurationError: If the integration cannot be configured
        """
        pass 