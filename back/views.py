from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from back.utils import generate_jwt  # Import de la fonction
from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
import json
import jwt
from django.conf import settings
from back.models import Administrateur

@csrf_exempt #On désactive temporairement le csrf
@api_view(['POST'])
@permission_classes([AllowAny]) #On dit que tous le monde peut y acceder
def generate_temp_token(request):
    """Génère un JWT temporaire pour un utilisateur non inscrit"""
    token = generate_jwt()  # Génère le JWT
    return Response({"access_token": token}) #On retourne le token en format json


@csrf_exempt  #  Désactive CSRF pour Postman (ne pas utiliser en production)
def add_admin(request):
    """Vue pour valider un token JWT et créer un administrateur"""
    if request.method == "POST":
        try:
            #  Récupérer le JSON envoyé
            data = json.loads(request.body)

            #  Vérifier si le token est bien présent
            token_to_validate = data.get("token")
            if not token_to_validate:
                return JsonResponse({"error": "Aucun token fourni"}, status=400)

            #  Décoder le token JWT
            secret_key = settings.SECRET_KEY
            decoded_payload = jwt.decode(token_to_validate, secret_key, algorithms=["HS256"])

            #  Vérifier les champs requis
            username = data.get("username")
            if not username:
                return JsonResponse({"error": "Le champ 'username' est vide."}, status=400)

            lastname = data.get("lastname")
            if not lastname:
                return JsonResponse({"error": "Le champ 'lastname' est vide."}, status=400)

            email = data.get("email")
            if not email:
                return JsonResponse({"error": "Le champ 'email' est vide."}, status=400)

            password = data.get("password")
            if not password:
                return JsonResponse({"error": "Le champ 'password' est vide."}, status=400)

            #  Hachage du mot de passe
            password_hashed = make_password(password)

            #  Vérifier si l'admin existe déjà (évite les doublons)
            if Administrateur.objects.filter(email=email).exists():
                return JsonResponse({"error": "Un administrateur avec cet email existe déjà."}, status=400)

            #  Création de l'administrateur
            admin = Administrateur(
                name=username,
                lastname=lastname,
                email=email,
                password=password_hashed
            )
            admin.save()

            #  Retourner une réponse JSON
            return JsonResponse({
                "message": "Administrateur créé avec succès",
                "payload": decoded_payload,
                "user_info": {"name": username, "lastname": lastname, "email": email}
            }, status=201)

        except json.JSONDecodeError:
            return JsonResponse({"error": "JSON invalide"}, status=400)
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token expiré"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Token invalide"}, status=403)

    return JsonResponse({"error": "Méthode non autorisée"}, status=405)