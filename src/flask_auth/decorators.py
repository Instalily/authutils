from functools import wraps
from flask import request, jsonify, current_app
import jwt

def require_role(allowed_roles: list[str] | None = None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization")
            if not auth or not auth.startswith("Bearer "):
                return jsonify({"message": "Missing token"}), 401
            try:
                token = auth.split()[1]
                payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])

                role = payload.get("role")
                if allowed_roles and role not in allowed_roles:
                    return jsonify({"message": "Forbidden"}), 403

            except jwt.ExpiredSignatureError:
                return jsonify({"message": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"message": "Invalid token"}), 401

            return f(*args, **kwargs)
        return wrapper
    return decorator
