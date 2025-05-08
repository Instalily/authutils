import secrets
import jwt
from datetime import datetime, timedelta, timezone

def init_auth(app):
    app.config['AUTH_SECRET_KEY'] = app.config.get('SECRET_KEY') or secrets.token_urlsafe(32)

def generate_token(user_id, role, token_type, app, expires_in_minutes=60):
    payload = {
        "user_id": user_id,
        "role": role,
        "token_type": token_type,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes)
    }
    return jwt.encode(payload, app.config['AUTH_SECRET_KEY'], algorithm='HS256')

def verify_token(token, app, expected_type=None):
    try:
        payload = jwt.decode(token, app.config['AUTH_SECRET_KEY'], algorithms=["HS256"])
        if expected_type and payload.get("token_type") != expected_type:
            return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None