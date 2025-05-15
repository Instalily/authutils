from enum import Enum

class ProviderTypeEnum(Enum):
    GOOGLE = "google"
    
class GrantTypeEnum(Enum):
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    