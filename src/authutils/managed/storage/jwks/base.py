from abc import ABC, abstractmethod
from ...providers import BackendAuthProvider
import httpx

class JWKSStorage(ABC):
    @abstractmethod
    def get_jwks(self, provider: BackendAuthProvider) -> dict:
        pass

    async def fetch_jwks(self, provider: BackendAuthProvider) -> dict:
        jwks_url = provider.get_jwks_url()
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(jwks_url)
                response.raise_for_status()
                jwks = response.json()
                return jwks
            except httpx.HTTPStatusError as e:
                raise ValueError(f"Failed to fetch JWKS for provider {provider.get_name()}: HTTP error at {jwks_url}: {e}")
            except httpx.RequestError as e:
                raise ValueError(f"Failed to fetch JWKS for provider {provider.get_name()}: Request error at {jwks_url}: {e}")
            except Exception as e:
                raise ValueError(f"Failed to fetch JWKS for provider {provider.get_name()}: Unexpected error at {jwks_url}: {e}")