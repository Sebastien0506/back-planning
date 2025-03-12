import jwt
import time
from datetime import datetime, timezone, timedelta
from django.conf import settings  # Importation de settings
from back.models import BlacklistedToken
from django.core.exceptions import PermissionDenied

def generate_jwt():
    """Génère un JWT simple"""
    expiration_time = datetime.now(tz=timezone.utc) + timedelta(minutes=30)
    encoded = jwt.encode({"some": "payload", "exp": expiration_time}, settings.SECRET_KEY, algorithm="HS256")
    return {"access_token": encoded}

def decoded_jwt(token) : 
    try : 
        jwt_decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])

        if jwt_decoded.get("exp", 0) < time.time() : 
            BlacklistedToken.objects.create(token=token)
            
            raise PermissionDenied("Le token a expiré !")
        
        return jwt_decoded
    except jwt.ExpiredSignatureError : 
        BlacklistedToken.objects.create(token=token)
        raise PermissionDenied("Le token a expiré")
    except jwt.InvalidTokenError : 
        raise PermissionDenied("Token invalide")
    
def expired_token() : 
    expired_time = datetime.now(tz=timezone.utc) - timedelta(minutes=1)
    encoded = jwt.encode({"some": "payload", "exp": expired_time}, settings.SECRET_KEY, algorithm="HS256")
    return {"access_token": encoded}