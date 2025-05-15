"""
Authentication provider implementations.

This package contains the base provider interface and concrete implementations
for various authentication providers (e.g., Google, GitHub, etc.).

The base provider interface defines the contract that all provider implementations
must follow, ensuring consistent behavior across different providers.
"""

from .base import BackendAuthProvider
from .google import GoogleAuthProvider

__all__ = [
    'BackendAuthProvider',  # Base interface
    'GoogleAuthProvider',   # Concrete implementation
]