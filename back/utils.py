import jwt
from datetime import datetime, timezone, timedelta
from django.conf import settings  # Importation de settings


def generate_jwt():
    """Génère un JWT simple"""
    expiration_time = datetime.now(tz=timezone.utc) + timedelta(minutes=30)
    encoded = jwt.encode({"some": "payload", "exp": expiration_time}, settings.SECRET_KEY, algorithm="HS256")
    return {"access_token": encoded}

