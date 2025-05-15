"""
Common exceptions used across the authutils package.
"""

class AuthUtilsError(Exception):
    """Base exception for all authutils errors."""
    pass

class ConfigurationError(AuthUtilsError):
    """Raised when there is a configuration error."""
    pass

class AuthenticationError(AuthUtilsError):
    """Raised when authentication fails."""
    pass

class TokenError(AuthUtilsError):
    """Raised when there is an error with token operations."""
    pass

class ProviderError(AuthUtilsError):
    """Raised when there is an error with an authentication provider."""
    pass

class StorageError(AuthUtilsError):
    """Raised when there is an error with storage operations."""
    pass 