# managed/models/types.py
from pydantic import BaseModel, Field # Import Field for potential aliases
from ...common.types.constants import GrantTypeEnum, ProviderTypeEnum

# --- Models for Incoming Request Body to /api/auth/token Endpoint ---
# This model represents the data sent by the frontend to your backend's token endpoint.
class TokenRequest(BaseModel):
    """
    Model for the incoming request body to the /api/auth/token endpoint.
    Handles both authorization_code and refresh_token grant types.
    """
    grant_type: GrantTypeEnum # "authorization_code" or "refresh_token"
    service: ProviderTypeEnum # Use the Enum type for validation

    # Fields specific to authorization_code grant (Optional, but required if grant_type is 'authorization_code')
    code: str | None = None
    redirect_uri: str | None = None
    state: str | None = None # State parameter from the callback URL

    # code_verifier is NOT sent by the frontend, it's retrieved from backend storage.
    # code_verifier: Optional[str] = None # <-- REMOVE THIS FIELD

    # Fields specific to refresh_token grant (Optional, but required if grant_type is 'refresh_token')
    refresh_token: str | None = None

    # You might add custom validation here using @model_validator or @validator
    # to ensure required fields are present based on the grant_type.
    # Example:
    # @model_validator(mode='after')
    # def check_grant_type_fields(self) -> 'TokenRequest':
    #     if self.grant_type == 'authorization_code':
    #         if not self.code or not self.redirect_uri or not self.state:
    #             raise ValueError("code, redirect_uri, and state are required for authorization_code grant.")
    #     elif self.grant_type == 'refresh_token':
    #         if not self.refresh_token:
    #             raise ValueError("refresh_token is required for refresh_token grant.")
    #     # Add checks for other grant types if supported
    #     return self


# --- Models for Internal Use (e.g., by exchange.py) ---
# These models represent the specific data needed for each grant type,
# including data retrieved internally (like code_verifier).
class AccessTokenRequestInternal(BaseModel): # Renamed to clarify internal use
    """Internal model for authorization_code grant request parameters."""
    code: str
    redirect_uri: str
    code_verifier: str # This comes from backend storage, not the frontend request body


class RefreshTokenRequestInternal(BaseModel): # Renamed to clarify internal use
    """Internal model for refresh_token grant request parameters."""
    refresh_token: str
    # redirect_uri is generally NOT required for refresh token requests


# --- Model for Successful Token Response from Identity Provider ---
# This model represents the structure of the successful response from the /token endpoint.
class TokenResponse(BaseModel):
    """Model for a successful response from an OAuth 2.0 / OIDC token endpoint."""
    id_token: str # The ID token (JWT)
    access_token: str # The access token
    refresh_token: str | None = None # Refresh token is optional
    expires_in: int # Lifetime of the access token in seconds
    token_type: str # e.g., "Bearer"
    scope: str | None = None # Scope is often optional in response

    # Some providers might return other fields, like 'token_id' or custom data.
    # You can add them here or use allow_extra=True in Pydantic config if needed.
    # model_config = {'extra': 'allow'} # Pydantic v2+ config for allowing extra fields


# --- Model for Error Response from Identity Service (Optional but Recommended) ---
# It's good practice to model the error responses from the provider as well.
class ProviderErrorResponse(BaseModel):
    """Model for an error response from an OAuth 2.0 / OIDC endpoint."""
    error: str # A single ASCII error code
    error_description: str | None = None # Human-readable ASCII text
    error_uri: str | None = None # URI for more info

    # model_config = {'extra': 'allow'} # Pydantic v2+ config for allowing extra fields


# --- Remove the Enum from this file ---
# BackendAuthServiceEnum # REMOVED