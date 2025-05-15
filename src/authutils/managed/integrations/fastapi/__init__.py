"""
FastAPI-specific authentication integrations.

This package provides FastAPI-specific implementations for both REST API and
WebSocket authentication, including dependency injection for protected routes
and WebSocket connection authentication.

The implementations handle token extraction, validation, and user context
management within the FastAPI framework.
"""

from .dependencies import create_fastapi_auth_dependency

__all__ = [
    'create_fastapi_auth_dependency',    # FastAPI dependency for REST API routes
]