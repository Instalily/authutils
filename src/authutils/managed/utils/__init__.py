"""
Utility functions for authentication flows.

This package provides utility functions for various authentication-related tasks,
including PKCE (Proof Key for Code Exchange) generation and state management.

The utilities are designed to be framework-agnostic and can be used across
different parts of the authentication system.
"""

from .pkce import (
    generate_code_verifier,    # Generate PKCE code verifier
    generate_code_challenge,   # Generate PKCE code challenge
    generate_csrf_state,       # Generate CSRF state parameter
)

__all__ = [
    'generate_code_verifier',    # PKCE code verifier generation
    'generate_code_challenge',   # PKCE code challenge generation
    'generate_csrf_state',       # CSRF state generation
]