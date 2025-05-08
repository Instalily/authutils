from functools import wraps
from flask import request, jsonify, current_app
from .auth import verify_token, AuthConfig
from .decorators import require_info

def flask_require_info(expected_info=None, auth_config: AuthConfig = None):
    def decorator(flask_handler):
        @require_info(expected_info)
        @wraps(flask_handler)
        def wrapper_flask(*args, **kwargs):
            cfg = auth_config or get_auth_config(current_app)
            if not cfg:
                return jsonify({"error": "server_error", "message": "Missing AuthConfig"}), 500

            auth = request.headers.get("Authorization")
            if not auth or not auth.startswith("Bearer "):
                return jsonify({"error": "unauthorized", "message": "Missing token"}), 401

            token = auth.split()[1]
            payload = verify_token(token, cfg)
            if not payload:
                return jsonify({"error": "unauthorized", "message": "Invalid or expired token"}), 401

            result = flask_handler(payload, *args, **kwargs)
            if isinstance(result, tuple):
                return jsonify(result[0]), result[1]
            return jsonify(result)

        return wrapper_flask
    return decorator