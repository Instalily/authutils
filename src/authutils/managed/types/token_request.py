from pydantic import BaseModel
from enum import Enum

class AuthProviderEnum(Enum):
    GOOGLE = "google"

class TokenRequest(BaseModel):
    code: str
    code_verifier: str
    redirect_uri: str
    provider: AuthProviderEnum
    refresh_token: str | None = None