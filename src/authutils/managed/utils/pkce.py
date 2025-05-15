# managed/utils/pkce.py
import os
import base64
import hashlib
import secrets # For generating random strings for state (optional, but good place for it)
from typing import Tuple # Import for type hints

# --- PKCE Generation Utilities ---
def generate_code_verifier(length: int = 96) -> str:
    """
    Generate a cryptographically secure random string for PKCE verifier.
    Length must be between 43 and 128 characters.
    """
    if not 43 <= length <= 128:
        raise ValueError("Code verifier length must be between 43 and 128.")
    # Generate random bytes and base64 URL-safe encode them
    random_bytes = os.urandom(length)
    return base64.urlsafe_b64encode(random_bytes).rstrip(b'=').decode('ascii')

def generate_code_challenge(verifier: str) -> str:
    """
    Generate the PKCE code challenge from the code verifier using the S256 method.
    """
    # Encode the verifier string to bytes
    verifier_bytes = verifier.encode('ascii')
    # Compute the SHA256 hash
    sha256_hash = hashlib.sha256(verifier_bytes).digest()
    # Base64 URL-safe encode the hash
    return base64.urlsafe_b64encode(sha256_hash).rstrip(b'=').decode('ascii')

# --- State Generation Utility ---
# This utility is also related to the initial auth request flow, so it fits well here
# It's used to create the 'state' parameter for CSRF protection and provider identification
def generate_csrf_state(provider_name: str) -> Tuple[str, str]:
    """
    Generate a unique state parameter including provider name and a CSRF token.

    Args:
        provider_name: The string name of the authentication provider.

    Returns:
        A tuple of (state, csrf_token) where state combines the provider name and CSRF token.
    """
    if not provider_name:
        raise ValueError("Provider name cannot be empty for state generation.")

    # Generate a random CSRF token
    csrf_token = secrets.token_urlsafe(32)

    # Combine provider name and CSRF token in the state parameter
    state = f"{provider_name}_{csrf_token}"
    return state, csrf_token # Return the full state string and the CSRF token part