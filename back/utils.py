import jwt
from datetime import datetime, timezone, timedelta
SECRET_KEY = "secret"

def generate_jwt():
    """Génère un JWT simple"""
    expiration_time = datetime.now(tz=timezone.utc) + timedelta(minutes=30)
    encoded = jwt.encode({"some": "payload", "exp": expiration_time}, SECRET_KEY, algorithm="HS256")
    return {"access_tokken" : encoded}