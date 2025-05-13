from pydantic import BaseModel

class AccessTokenRequest(BaseModel):
    code: str
    code_verifier: str
    redirect_uri: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str
    redirect_uri: str
