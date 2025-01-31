from django.test import TestCase
import jwt
from datetime import datetime, timezone
from back.utils import generate_jwt  # Import de la fonction
from django.conf import settings
import json
from django.http import JsonResponse
import bcrypt
class JWTExpirationTest(TestCase):

    def test_hasher_password(password) : 
        password = b"monpassword"

        hashed = bcrypt.hashpw(password, bcrypt.gensalt())

        if bcrypt.checkpw(password, hashed) :
            print("It Matches!")
        else : 
            print("It Does not Match :(")

        print(hashed)


    # def validate_jwt_token(self, token_to_validate): 
    #     """Valide un token JWT"""
    #     secret_key = settings.SECRET_KEY
    #     algorithm = 'HS256'

    #     try:
    #         decoded_payload = jwt.decode(token_to_validate, secret_key, algorithms=[algorithm])
    #         return decoded_payload
    #     except jwt.ExpiredSignatureError: 
    #         return "Token is expired. Please log in again."
    #     except jwt.InvalidTokenError: 
    #         return "Invalid token. Access denied."
    #     return None
    
    # def test_submit_token(self, request): 
    #     """Test de validation d'un token JWT"""
    #     if request.method == "POST" :
    #         try :
    #             data = json.loads(request.body)
    #         except : 
    #             return JsonResponse({"message": "Le token n'a pas été reçut."})
            
    #     token_to_validate = data
    #     decoded_payload = self.validate_jwt_token(token_to_validate)

    #     # Vérifie si le token est bien décodé
    #     if isinstance(decoded_payload, dict):
    #         print("Token valide :", decoded_payload)
    #         self.assertIn("some", decoded_payload)  # Vérifie que la clé "some" est présente
    #     else:
    #         print("Erreur :", decoded_payload)
    #         self.assertTrue(decoded_payload in ["Token is expired. Please log in again.", "Invalid token. Access denied."])

    # def my_view(request):
    #     if request.method == "POST":
    #         try:
    #             data = json.loads(request.body)  # Convertir JSON en dict
    #             if data :

    #             return JsonResponse({"message": "Données reçues", "data": data})
    #         except json.JSONDecodeError:
    #             return JsonResponse({"error": "JSON invalide"}, status=400)
