from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from back.utils import generate_jwt  # Import de la fonction
from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse
import json
import jwt
from django.conf import settings
from back.models import Administrateur, Employes
from django.middleware.csrf import get_token
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

#ROUTE QUI PERMET DE GENERER UN JWT TOKEN
@csrf_exempt #On désactive temporairement le csrf
@api_view(['POST'])
@permission_classes([AllowAny]) #On dit que tous le monde peut y acceder
def generate_temp_token(request):
    """Génère un JWT temporaire pour un utilisateur non inscrit"""
    token = generate_jwt()  # Génère le JWT
    return Response({"access_token": token}) #On retourne le token en format json

def get_csrf_token(request) :
    if request.method == "GET" : 
        token = get_token(request)
        return JsonResponse({'csrfToken': token}) 
    
#ROUTE QUI PERMET DE CREER UN ADMINISTRATEUR
@csrf_exempt  #  Désactive CSRF pour Postman (ne pas utiliser en production)
@api_view
@permission_classes([AllowAny])
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

@api_view(['POST'])
@csrf_exempt
@permission_classes([AllowAny])
def login(request):
    if request.method != "POST":
        return JsonResponse({"error": "Seules les requêtes POST sont autorisées."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    try:
        data = json.loads(request.body)
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return JsonResponse({"error": "Nom d'utilisateur et mot de passe sont requis."}, status=status.HTTP_400_BAD_REQUEST)

        # Recherche de l'utilisateur dans les deux tables
        user = None
        role = None

        # Vérification dans Administrateur
        try:
            user = Administrateur.objects.get(username=username)
            role = "admin"
        except Administrateur.DoesNotExist:
            pass

        # Vérification dans Employes si non trouvé en admin
        if not user:
            try:
                user = Employes.objects.get(username=username)
                role = "employe"
            except Employes.DoesNotExist:
                pass

        # Vérification du mot de passe
        if not user or not check_password(password, user.password):
            return JsonResponse({"error": "Identifiants incorrects."}, status=status.HTTP_401_UNAUTHORIZED)

        # Génération des tokens
        refresh = RefreshToken.for_user(user)
        
        # Réponse sécurisée
        response = JsonResponse({
            "username": user.username
        })

        # Stocker le JWT dans un cookie HttpOnly sécurisé
        response.set_cookie(
            key='access_token',
            value=str(refresh.access_token),
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=3600
        )

        # Stocker le rôle uniquement pour l'affichage côté frontend (sans impact sur la sécurité)
        response.set_cookie(
            key='user_role',
            value=role,
            httponly=False,
            secure=True,
            samesite='Strict',
            max_age=3600
        )

        return response

    except json.JSONDecodeError:
        return JsonResponse({"error": "Données JSON invalides."}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return JsonResponse({"error": f"Erreur inattendue : {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



