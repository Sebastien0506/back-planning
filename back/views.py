from django.views.decorators.csrf import csrf_protect, csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from back.utils import generate_jwt  # Import de la fonction
from back.serializer import AdministrateurSerializer, LoginSerializer
from django.contrib.auth.hashers import make_password, check_password
from django.http import JsonResponse
import json
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError, DecodeError
from django.conf import settings
from back.models import Administrateur, Employes, Magasin, Contrats
from django.middleware.csrf import get_token
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import datetime
from django.core.mail import send_mail
import logging


#ROUTE QUI PERMET DE GENERER UN JWT TOKEN
# @csrf_exempt #On désactive temporairement le csrf
@api_view(['POST'])
@permission_classes([AllowAny]) #On dit que tous le monde peut y acceder
def generate_temp_token(request):
    """Génère un JWT temporaire pour un utilisateur non inscrit"""
    token = generate_jwt()  # Génère le JWT
    return Response({"access_token": token}) #On retourne le token en format json

@api_view(["GET"])
@permission_classes([AllowAny])
@csrf_exempt
def get_csrf_token(request) :
    token = get_token(request)
    response = JsonResponse({"message" : "Jeton CSRF récupérer avec succès."})
    response.set_cookie(
        key='csrftoken',
        value=token,
        httponly=False,
        secure=False,
        samesite="Lax"
    )
    return response
        
  
@api_view(['POST'])  # Accepte uniquement les requêtes POST
@csrf_protect
@permission_classes([AllowAny])  # Autorise tout le monde à accéder à cette route
def add_admin(request):
    """Vue pour valider un token JWT et créer un administrateur"""
    if request.method != "POST" : 
        return JsonResponse({"error" : "Seul les méthodes POST sont accepter"}, status.HTTP_405_METHOD_NOT_ALLOWED)

    try:
        # Récupérer le JSON envoyé
        # data = request.data

        # Vérifier si le token est bien présent
        token_to_validate = request.data.get("token")
        if not token_to_validate:
            return JsonResponse({"error": "Aucun token fourni"}, status=400)

        # Décoder le token JWT
        secret_key = settings.SECRET_KEY
        try:
            decoded_payload = jwt.decode(token_to_validate, secret_key, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token expiré"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Token invalide"}, status=403)

        

        # Valider les données avec le sérialiseur
        serializer = AdministrateurSerializer(data=request.data)
        if serializer.is_valid():
            # Vérifier si l'admin existe déjà (évite les doublons)
            if Administrateur.objects.filter(email=request.data.get("email")).exists():
                return JsonResponse({"error": "Un administrateur avec cet email existe déjà."}, status=400)

            # Hacher le mot de passe avant la sauvegarde
            serializer.validated_data['password'] = make_password(serializer.validated_data['password'])

            # Sauvegarder l'administrateur
            serializer.save()

            # Retourner une réponse JSON de succès
            return JsonResponse({
                "message": "Administrateur créé avec succès",
                "payload": decoded_payload,
                "user_info": {
                    "username": serializer.data["username"],
                    "lastname": serializer.data["lastname"],
                    "email": serializer.data["email"]
                }
            }, status=201)
        else:
            # Retourner les erreurs de validation
            return JsonResponse({"errors": serializer.errors}, status=400)

    except json.JSONDecodeError:
        return JsonResponse({"error": "JSON invalide"}, status=400)
    except Exception as e:
        # Gérer les erreurs imprévues
        return JsonResponse({"error": str(e)}, status=500)

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    logger = logging.getLogger(__name__)
    """Authentifie un utilisateur et renvoie un token JWT"""

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
        refresh = RefreshToken.for_user(user)

        # Création de la réponse sécurisée
        response = Response({
            "username": user.username,
            "role": role
        })

        # Stockage du token JWT en HttpOnly Cookie sécurisé
        response.set_cookie(
            key='access_token',
            value=str(refresh.access_token),
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=3600,
        )

        # Stocker le rôle pour le frontend (accessible par JS)
        response.set_cookie(
            key='user_role',
            value=role,
            httponly=False,
            secure=True,
            samesite='Strict',
            max_age=3600,
        )

        return response

    except Exception as e:
        return Response({"error": f"Erreur serveur : {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
# @csrf_exempt
@api_view(['POST'])
@permission_classes(Administrateur)
def add_employes(request) :
    if request.method == 'POST' : 
        try : 
            data = json.loads(request.body)

            username = data.get('username')
            lastname = data.get('lastname')
            email = data.get('email')
            heure_debut_str = data.get('horaire_debut')
            heure_fin_str = data.get('horaire_fin')

            try : 
                start_job = datetime.strptime(heure_debut_str, "%H:%M").time()
                end_job = datetime.strptime(heure_fin_str, "%H:%M").time()
            except :
                return JsonResponse({"error" : "Format d'heure invalide. Format attendu : HH:MM"})
            
            if not all(isinstance(field, str) for field in [username, lastname, email]) :
                return JsonResponse({"error" : "Tous les champs doivent être des chaines de caractères." }, status=status.HTTP_400_BAD_REQUEST)
            
            jours_de_travail = data.get("jours_de_travail")
            jours_valide = ["lundi", "mardi", "mercrdi", "jeudi", "vendredi", "samedi", "dimanche"]

            if not isinstance(jours_de_travail, dict):
                return JsonResponse({"error" : "Le champ 'jours_de_travail', doit être un dictionnaire."}, status=status.HTTP_400_BAD_REQUEST)
            

            for jour, valeur in jours_de_travail.item() : 
                jour_normalise = jour.strip().lower()
                if jour_normalise not in jours_valide : 
                    return JsonResponse({"error" : f"Le jour '{jour}' n'est pas une valeur valide."}, status=status.HTTP_400_BAD_REQUEST)
                if valeur.strip().lower() != "travail" : 
                    return JsonResponse({"error" : f"La valeur associée au jour '{jour}' doit être 'travail'. "}, status=status.HTTP_400_BAD_REQUEST)
            
            #Envoie du mail pour que l'employer renseigne sont mot de passe
            send_mail(
                subject='Inscription',
                message="Vous avez été enregistrer veuillez modifier votre mot de passe en cliquant sur ce lien.",
                from_email='From generatePlanning@gmail.com',
                 html_message="""
        <p>Vous avez été enregistré. Veuillez modifier votre mot de passe en cliquant sur ce lien :</p>
        <p><a href="https://example.com/reset-password/">Modifier mon mot de passe</a></p>
    """
            )
            return JsonResponse({"message" : "Jours de travail valide."}, status=status.HTTP_200_OK)
        except : 
            return JsonResponse({"error" : "Erreur lors de la création de l'employer."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

@api_view(['POST'])
# @csrf_exempt
@permission_classes([AllowAny])
def add_shop(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Seules les requêtes POST sont autorisées."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    try:
        # Charger les données JSON
        data = json.loads(request.body)

        # Récupération et validation du champ "name"
        name_shop = data.get('name')

        # Vérifier que le champ est une chaîne et non vide
        if not isinstance(name_shop, str) or not name_shop.strip():
            return JsonResponse(
                {"error": "Le champ 'name' doit être une chaîne de caractères non vide."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Création et sauvegarde du nouveau magasin
        new_shop = Magasin(name=name_shop.strip())
        new_shop.save()

        # Retourner une réponse de succès
        return JsonResponse(
            {"message": f"La boutique '{name_shop}' a été créée avec succès."},
            status=status.HTTP_201_CREATED
        )

    except json.JSONDecodeError:
        return JsonResponse({"error": "Le format JSON est invalide."}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return JsonResponse({"error": f"Erreur lors de la création de la boutique : {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    

@api_view(['POST'])
# @csrf_exempt
@permission_classes([AllowAny])
def add_contrat(request):
    # Vérifier que la méthode est POST
    if request.method != 'POST':
        return JsonResponse({"error": "Seules les requêtes POST sont autorisées."}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    try:
        # Charger et vérifier les données JSON
        data = json.loads(request.body)
        contrat = data.get("type_de_contrat")

        # Validation du champ "type_de_contrat"
        if not isinstance(contrat, str) or not contrat.strip():
            return JsonResponse({"error": "Le champ 'type_de_contrat' doit être une chaîne de caractères non vide."}, status=status.HTTP_400_BAD_REQUEST)

        # Optionnel : restreindre les contrats autorisés
        contrats_autorises = ["CDI", "CDD", "Stage"]
        if contrat.strip() not in contrats_autorises:
            return JsonResponse({
                "error": f"Le type de contrat '{contrat}' n'est pas autorisé. Types autorisés : {', '.join(contrats_autorises)}."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Création et sauvegarde du contrat
        new_contrat = Contrats(type_de_contrat=contrat.strip())
        new_contrat.save()

        # Réponse de succès
        return JsonResponse({
            "message": f"Le contrat '{contrat}' a été ajouté avec succès.",
            "contrat": contrat.strip()
        }, status=status.HTTP_201_CREATED)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Le format JSON est invalide."}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return JsonResponse({"error": f"Erreur lors de la création du contrat : {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
        
 



                
            
    
    

