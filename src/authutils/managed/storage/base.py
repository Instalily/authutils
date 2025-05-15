"""
Base interfaces for storage implementations.
"""

from abc import ABC, abstractmethod
from typing import Optional, Tuple

from ...common.types import ProviderTypeEnum
from ...common.exceptions import StorageError

class PKCEStorage(ABC):
    """Base interface for PKCE storage implementations."""
    
    @abstractmethod
    async def store(self, state: str, code_verifier: str, provider: ProviderTypeEnum) -> None:
        """
        Store PKCE details for a given state.
        
        Args:
            state: The state parameter from the auth flow
            code_verifier: The PKCE code verifier
            provider: The authentication provider
            
        Raises:
            StorageError: If storage operation fails
        """
        pass
    
    @abstractmethod
    async def retrieve_and_clear(self, state: str) -> Tuple[str, ProviderTypeEnum]:
        """
        Retrieve and clear PKCE details for a given state.
        
        Args:
            state: The state parameter from the auth flow
            
        Returns:
            Tuple of (code_verifier, provider)
            
        Raises:
            StorageError: If storage operation fails
        """
        pass

class JWKSStorage(ABC):
    """Base interface for JWKS storage implementations."""
    
    @abstractmethod
    async def get_jwks(self, provider: ProviderTypeEnum) -> dict:
        """
        Get JWKS for a provider.
        
        Args:
            provider: The authentication provider
            
        Returns:
            The JWKS document
            
        Raises:
            StorageError: If storage operation fails
        """
        pass
    
    @abstractmethod
    async def fetch_jwks(self, provider: ProviderTypeEnum) -> dict:
        """
        Fetch fresh JWKS for a provider.
        
        Args:
            provider: The authentication provider
            
        Returns:
            The JWKS document
            
        Raises:
            StorageError: If storage operation fails
        """
        pass 