from typing import Dict, Any
from .services import AuthService # Import the interface
from .models import AuthServiceEnum, AuthorizationTokenRequest, RefreshTokenRequest
from datetime import datetime, timedelta
import httpx
from jose import jwt, JOSEError

class AuthServiceRegistry:
    """
    Registry for backend authentication services.
    Provides access to service configurations by name.
    Also, allows for token exchange and verification.
    """
    def __init__(self):
        self._services: Dict[AuthServiceEnum, AuthService] = {}

        self._jwks_cache: Dict[AuthServiceEnum, Dict[str, Any]] = {}
        self._jwks_cache_time: Dict[AuthServiceEnum, datetime] = {}
        self.JWKS_CACHE_TIME = 1 # Hours

    def register_service(self, service: AuthService):
        """
        Register a backend auth service.
        """
        if not isinstance(service, AuthService):
            print(f"Warning: Registered object is not an instance of AuthService: {service}")
            raise TypeError("Registered service must be an instance of AuthService")

        self._services[service.get_type()] = service
        print(f"Registered backend auth service: {service.get_type()}")

    def get_service(self, service_type: AuthServiceEnum) -> AuthService:
        """
        Get a registered backend auth service by name.
        """
        service = self._services.get(service_type)
        if not service:
            raise ValueError(f"Backend auth service '{service_type}' not found in registry.")
        return service

    def has_service(self, service_type: AuthServiceEnum) -> bool:
        """
        Check if a service is registered.
        """
        return service_type in self._services

    def get_all_services(self) -> list[AuthService]:
        """
        Get all registered backend auth services.
        """
        return list(self._services.values())
    
    def exchange_authorization_code(self, authorization_token_request: AuthorizationTokenRequest, auth_service: AuthServiceEnum) -> Dict[str, Any]:
        """
        Exchange a code for a token.
        """
        service = self._services[auth_service]
        if not service:
            raise ValueError(f"Service not found in registry: {auth_service}")
        
        return service.exchange_authorization_code(authorization_token_request)
    
    def exchange_refresh_token(self, refresh_token_request: RefreshTokenRequest, auth_service: AuthServiceEnum) -> Dict[str, Any]:
        """
        Exchange a refresh token for a new access token.
        """
        service = self._services[auth_service]
        if not service:
            raise ValueError(f"Service not found in registry: {auth_service}")
        
        return service.exchange_refresh_token(refresh_token_request)
    
    async def _get_jwks(self, service_type: AuthServiceEnum) -> Dict[str, Any]:
        """
        Get the JWKS for a given auth service.
        """
        if service_type not in self._services:
            raise ValueError(f"Service not found in registry: {service_type}")
        
        current_time = datetime.now()
        if service_type in self._jwks_cache and self._jwks_cache_time[service_type] < current_time - timedelta(hours=self.JWKS_CACHE_TIME):
            return self._jwks_cache[service_type]
        
        jwks_url = self._services[service_type].get_jwks_url()
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(jwks_url)
                response.raise_for_status()
                jwks = response.json()
                self._jwks_cache[service_type] = jwks
                self._jwks_cache_time[service_type] = current_time
                return jwks
            except httpx.HTTPStatusError as e:
                raise ValueError(f"Failed to fetch JWKS for service: HTTP error {service_type}: {e}")
            except httpx.RequestError as e:
                raise ValueError(f"Failed to fetch JWKS for service: Request error {service_type}: {e}")
            except Exception as e:
                raise ValueError(f"Failed to fetch JWKS for service: Unexpected error {service_type}: {e}")
            
    async def verify_id_token(
        self,
        id_token: str,
        auth_service: AuthServiceEnum
    ) -> Dict[str, Any]:
        """
        Verifies the ID token signature and claims.

        Args:
            id_token: The ID token string from the Authorization header.
            jwks_url: The URL of the identity provider's JWKS endpoint.
            issuer: The expected issuer (iss claim) of the token.
            audience: The expected audience (aud claim) of the token (your client ID).

        Returns:
            The decoded and validated token payload (claims).

        Raises:
            ValueError: If the token is invalid (signature, claims, etc.).
        """
        if not id_token:
            raise ValueError("ID token is missing.")
        
        auth_service = self._services[auth_service]
        if not auth_service:
            raise ValueError(f"Service not found in registry: {auth_service}")

        try:
            # Verify the token signature and validate standard claims (exp, iat, nbf)
            # python-jose handles finding the correct key from the JWKS automatically
            decoded_token = jwt.decode(
                token=id_token,
                key=await self._get_jwks(auth_service), # Pass the JWKS dictionary
                algorithms=["RS256"], # Specify the expected signing algorithm(s)
                issuer=auth_service.get_issuer_url(), # Validate the 'iss' claim
                audience=auth_service.get_client_id(), # Validate the 'aud' claim
                options={
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    # Add other options as needed
                }
            )
            print("ID token signature and standard claims verified successfully.")

            # You might add additional custom claim validations here if needed
            # e.g., check for specific roles or permissions in the claims

            return decoded_token # Return the validated claims

        except JOSEError as e:
            # Catch any errors during decoding or validation
            print(f"ID token verification failed: {e}")
            raise ValueError(f"Invalid token: {e}") from e
        except Exception as e:
            # Catch any other unexpected errors
            print(f"An unexpected error occurred during token verification: {e}")
            raise ValueError(f"Token verification failed due to an internal error: {e}") from e