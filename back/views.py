from django.views.decorators.csrf import csrf_protect, csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from back.serializer import AdministrateurSerializer, LoginSerializer
from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse
import json
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError
from django.conf import settings
from back.models import Administrateur, Employes, Magasin, Contrats, BlacklistedToken
from django.middleware.csrf import get_token
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import datetime
from rest_framework_simplejwt.tokens import RefreshToken
import logging
from back.utils import generate_jwt, decoded_jwt

    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request) : 
    ###
    # CODE POUR GÉRER LA DECONNEXION
    # ####
    try : 
        access_token = request.COOKIES.get('access_token')

        if not access_token : 
            return Response({"error" : "Aucun token trouvé"}, status=status.HTTP_400_BAD_REQUEST)
        
        BlacklistedToken.objects.create(token=access_token)
        refresh_token = request.data.get('refresh_token')

        if refresh_token : 
            try :
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception as e : 
                return Response({"error" : f"Erreur lors de la révocations du refresh token : {str(e)}"},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        response = Response({"message" : "déconnexion réussie."}, status=status.HTTP_200_OK)
        response.delete_cookie('access_token')
        response.delete_cookie("user_id")
        response.delete_cookie('user_role')

        return response
    except Exception as e : 
        return Response({"error" : f"Erreur serveur : {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_user_role(request) : 
    #
    # CODE POUR RÉCUPERER LE ROLE DE L'UTILISATEUR
    # #
    if request.method != 'GET' :
        return JsonResponse({"error" : "La méthode doit être POST"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    try : 
        user_role = request.COOKIES.get("user_role")
        if not user_role : 
            return Response({"error" : "Utilisateur non authentifié."}, status=status.HTTP_401_UNAUTHORIZED)
        return Response({"role" : user_role})
    except Exception as e : 
        return Response({"error" : f"Erreur serveur :{str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@api_view(["GET"])
@permission_classes([AllowAny])
@csrf_exempt
def get_csrf_token(request) :
    ###
    # CODE POUR GÉNERER UN TOKEN
    # ###
    token = get_token(request)
    response = JsonResponse({"message" : "Jeton CSRF récupérer avec succès."})
    response.set_cookie(
        key='csrftoken',
        value=token,
        httponly=False,
        secure=False,
        samesite="Strict"
    )
    return response
        
  
@api_view(['POST'])
@permission_classes([AllowAny])
def add_admin(request):
    try:
        # Stocker les données de la requête dans une variable pour éviter de relire request.data plusieurs fois
        data = request.data  

        if not data:
            return Response({"error": "Les données sont manquantes."}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier si un administrateur avec cet email existe déjà
        if Administrateur.objects.filter(email=data.get("email")).exists():
            return Response({"error": "Un administrateur avec cet email existe déjà."}, status=status.HTTP_400_BAD_REQUEST)

        # Valider les données avec le sérialiseur
        serializer = AdministrateurSerializer(data=data)
        if serializer.is_valid():
            # Hacher le mot de passe avant de sauvegarder
            serializer.validated_data['password'] = make_password(serializer.validated_data['password'])

            # Créer et sauvegarder l'administrateur avec les données modifiées
            admin = Administrateur(**serializer.validated_data)
            admin.save()

            response = Response({"message": "Administrateur créé avec succès."}, status=status.HTTP_201_CREATED)

            # Définir un cookie sécurisé pour stocker le rôle
            response.set_cookie(
                key="user_role",
                value="admin",
                httponly=False,
                secure=False,
                samesite="Strict",
            )

            return response
        else:
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    logger = logging.getLogger(__name__)
    

    try:
        # Vérification des données reçues
        if not request.data:
            return Response({"error": "Données manquantes."}, status=status.HTTP_400_BAD_REQUEST)


        # Validation des identifiants via le Serializer
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        # Recherche de l'utilisateur (Admin ou Employé)
        user = Administrateur.objects.filter(email=email).first()
        role = "admin" if user else None

        if not user:
            user = Employes.objects.filter(email=email).first()
            role = "employe" if user else None

        if not user:
            logger.warning(f"Utilisateur non trouvé avec email : {email}")
            return Response({"error": "Identifiants incorrects."}, status=status.HTTP_401_UNAUTHORIZED)

        # Vérification du mot de passe
        if not check_password(password, user.password):
            logger.warning(f"Mot de passe incorrect pour l'utilisateur: {user.email}")
            return Response({"error": "Identifiants incorrects."}, status=status.HTTP_401_UNAUTHORIZED)

        # Génération des tokens JWT
        # refresh = RefreshToken.for_user(user)

        jwt = generate_jwt()
        # Création de la réponse sécurisée
        response = Response({
            "role": role
        })
        
        response.set_cookie(
            key="access_token",
            value=jwt,
            httponly=True,
            secure=True,
            samesite="Strict",
        )
        
        response.set_cookie(
            key='user_id',
            value=user.id,
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=3600,
        )
        response.set_cookie(
            key="user_role",
            value=role,
            httponly=True,
            secure=True,
            samesite="Strict",
            max_age=3600,
        )

        return response

    except Exception as e:
        return Response({"error": f"Erreur serveur : {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
# @csrf_exempt
@api_view(["POST"])
@permission_classes([Administrateur])  # Correction de la syntaxe
def add_employes(request):
    
        

@api_view(['POST'])
# @csrf_exempt
@permission_classes([AllowAny])
def add_shop(request):
    
    
    

@api_view(['POST'])
# @csrf_exempt
@permission_classes([AllowAny])
def add_contrat(request):
   
    
        
 



                
            
    
    

