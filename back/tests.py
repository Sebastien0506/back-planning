from django.test import TestCase
import jwt
from datetime import datetime, timezone
from back.utils import generate_jwt  # Import de la fonction
from rest_framework.response import Response

SECRET_KEY = "secret"

class JWTExpirationTest(TestCase):

    def test_generate_jwt_with_expiration(request):
        token_data = generate_jwt()

        return Response(token_data)