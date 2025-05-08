from functools import wraps
from .auth import validate_token_claims

def require_info(expected_info: dict[str, list[str]] | None = None):
    def decorator(handler):
        @wraps(handler)
        def wrapper(payload: dict, *args, **kwargs):
            if expected_info:
                ok, reason = validate_token_claims(payload, expected_info)
                if not ok:
                    return {"error": "forbidden", "message": reason}, 403
            return handler(payload, *args, **kwargs)
        return wrapper
    return decorator