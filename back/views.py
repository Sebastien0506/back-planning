from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from back.serializer import UserSerializer, LoginSerializer, ShopSerializer,ContratSerializer, AddEmployerSerializer, ListContratSerializer, ListEmployerSerializer, DetailEmployerSerializer, ListShopSerializer, CheckVacationSerializer, VacationSerializer
from django.contrib.auth.hashers import make_password, check_password
from back.models import User, Magasin, Contrat, WorkingDay, Vacation
from django.middleware.csrf import get_token
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
import traceback
import logging
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from rest_framework import status, permissions

User = get_user_model()
class LogoutView(APIView) :
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request) : 
        refresh_token = request.COOKIES.get('refresh_token')
        if refresh_token is None : 
            return Response({"detail" : "Refresh token non trouvé dans les cookies."}, status=status.HTTP_400_BAD_REQUEST)
        
        try : 
            token = RefreshToken(refresh_token)
            token.blacklist()
            
        
        except (TokenError, InvalidToken) :
            return Response({"detail" : "Token invalide ou déjà blacklisté."}, status=status.HTTP_400_BAD_REQUEST)
        
        response = Response({"detail" : "Déconnexion réussie."}, status=status.HTTP_205_RESET_CONTENT)
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        return response

@api_view(["GET"])
@permission_classes([AllowAny])
def get_user_role(request):
    token = request.COOKIES.get("access_token")

    if not token:
        print("❌ Pas de token dans les cookies")
        return Response({"error": "Token manquant"}, status=status.HTTP_401_UNAUTHORIZED)

    jwt_auth = JWTAuthentication()
    try:
        validated_token = jwt_auth.get_validated_token(token)
        user = jwt_auth.get_user(validated_token)
    except Exception as e:
        print("❌ Erreur inconnue lors de la validation du token :")
        traceback.print_exc()  # 🔥 Affiche tout dans le terminal
        response = Response({"error": "Token invalide ou expiré"}, status=status.HTTP_401_UNAUTHORIZED)
        response.delete_cookie("access_token")
        return response

    role = user.role if hasattr(user, 'role') else "unknown"
    return Response({"role": role}, status=status.HTTP_200_OK)
    
@api_view(['POST'])
@permission_classes([AllowAny])
def add_admin(request):
    try:
        # Stocker les données de la requête dans une variable pour éviter de relire request.data plusieurs fois
        data = request.data  

        if not data:
            return Response({"error": "Les données sont manquantes."}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier si un administrateur avec cet email existe déjà
        if User.objects.filter(email=data.get("email")).exists():
            return Response({"error": "Un administrateur avec cet email existe déjà."}, status=status.HTTP_400_BAD_REQUEST)

        # Valider les données avec le sérialiseur
        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            # Hacher le mot de passe avant de sauvegarder
            serializer.validated_data['password'] = make_password(serializer.validated_data['password'])

            # Créer et sauvegarder l'administrateur avec les données modifiées
            user = User(**serializer.validated_data)
            user.role = "superadmin"
            user.save()

            response = Response({"message": "Administrateur créé avec succès."}, status=status.HTTP_201_CREATED)

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                secure=False,
                samesite="None",
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

        # Recherche de l'utilisateur
        user = User.objects.filter(email=email).first()
        #Si l'utilisateur n'est pas dans la base de donnée on renvoi un message d'erreur.
        if not user : 
            return Response({"error" : "Utilisateur non trouvée."}, status=status.HTTP_401_UNAUTHORIZED)

        # Vérification du mot de passe
        if not check_password(password, user.password):
            logger.warning(f"Mot de passe incorrect pour l'utilisateur: {user.email}")
            return Response({"error": "Identifiants incorrects."}, status=status.HTTP_401_UNAUTHORIZED)

        # Génération des tokens JWT
        # refresh = RefreshToken.for_user(user)

        refresh_token = RefreshToken.for_user(user)
        access_token = str(refresh_token.access_token)
        # Création de la réponse sécurisée
        response = Response({
            "message" : "Connexion réussie"
        })
        csrf_token = get_token(request)
        response.set_cookie(
            key='csrftoken',
            value=csrf_token,
            httponly=False,
            secure=False,
            samesite='None',
            max_age=300
        )
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            httponly=True,
            secure=True,
            samesite='None',
            max_age=300
        )
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,
            samesite="None",
            max_age=300
        )

        return response

    except Exception as e:
        return Response({"error": f"Erreur serveur : {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#Class pour gérer les magasins
class ShopView(APIView) : 
    permission_classes = [IsAuthenticated]
    #Ajout d'un magasin
    def post(self, request) :
        try : 
            if request.user.role != "superadmin" :
                return Response({"error" : "Vous n'avez pas la permission de créer un magasin"}, status=status.HTTP_403_FORBIDDEN)
            
            if not request.data : 
                return Response({"error" : "Les données sont manquantes."}, status=status.HTTP_400_BAD_REQUEST)
            
            serializer = ShopSerializer(data=request.data)
            if not serializer.is_valid() : 
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            magasin = serializer.save()
            magasin.created_by.add(request.user)
            magasin.save()

            return Response({
                "message" : "Magasin créé et associé avec succès.",
                "magasin_id" : magasin.id
            }, status=status.HTTP_201_CREATED)
        except Exception as e : 
            return Response({"error" : str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    #Modification d'un magasin
    def put(self, request, shop_id) :
        #On vérifie le role de l'utilisateur 
        if request.user.role != "superadmin" : 
            return Response({"error" : "Vous n'avez pas la permission de modifier un magasin."}, status=status.HTTP_401_UNAUTHORIZED)
        
        try : 
            #On initialise le serializer
            serializer = ShopSerializer(data=request.data)

            #On vérifie si le serializer est valide
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            #On récupère les données du serializer
            data = serializer.validated_data
            
            try :
                #On récupère le magasin à modifier
                shop = Magasin.objects.get(id=shop_id)
            except Exception as e :
                return Response({"error" : str(e)}, status=status.HTTP_404_NOT_FOUND)
            #On met à jour le nom
            shop.shop_name = data["shop_name"]
            shop.save()
            return Response({"message" : "Le nom du magasin a bien été modifier."}, status=status.HTTP_200_OK)
        except Exception as e : 
            return Response({"error" : str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    #Suppression d'un magasin
    def delete(self, request, shop_id) :
        if request.user.role != "superadmin" :
            return Response({"error" : "Vous n'avez pas la permission de supprimer un magasin."}, status=status.HTTP_403_FORBIDDEN)
        try : 
            magasin = Magasin.objects.get(id=shop_id)
            magasin.delete()
            return Response({"message" : "Magasin supprimer avec succès."}, status=status.HTTP_200_OK)
        except Magasin.DoesNotExist : 
            return Response({"error" : "Magasin introuvable."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e : 
            return Response({"error" : str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ContratView(APIView) : 
    permission_classes = [IsAuthenticated]
    def post(self, request) :
        #On vérifie si la requete à bien la méthode post
        if request.method != "POST" :
            return Response({"error" : "Uniquement la méthode 'POST' est accepter."}, 
                            status=status.HTTP_405_METHOD_NOT_ALLOWED
                            )
        try :
            #On vérifie si l'utilisateur à bien le role superadmin
            if request.user.role != "superadmin" : 
                return Response({"error" : "Vous n'avez pas la permission d'ajouter des contrat."},
                                status=status.HTTP_403_FORBIDDEN
                                )
            #On vérifie que la requête contient bien des données.
            if not request.data : 
                return Response({"error" : "Les données sont manquante."},
                                status=status.HTTP_400_BAD_REQUEST)
            #On initialise les données pour le serializer
            serializer  = ContratSerializer(data=request.data)
            
            #On vérifie si le serializer est valide 
            if not serializer.is_valid() :
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            #On sauvegarde les données
            contrat = serializer.save()
            contrat.save()
            #On retourne un réponse
            return Response({
                "message" : "Contrat crée avec succès.",
                "contrat_id" : contrat.id
            }, status=status.HTTP_201_CREATED)
        #On gère les exceptions
        except Exception as e :
            return Response({"error" : str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    def delete(self, request, contrat_id) :
        #On vérifie le role de l'utilisateur qui fait la requête
        if request.user.role != "superadmin" :
            return Response({"error" : "Vous n'avez pas la permission de supprimer un contrat."}, status=status.HTTP_401_UNAUTHORIZED)
        
        try :
            #On récupère le contrat
            contrat = Contrat.objects.get(id=contrat_id)
            contrat.delete()
            return Response({"message" : "Le contrat à bien été supprimer avec succès."}, status=status.HTTP_200_OK)
        except Contrat.DoesNotExist :
            #Si le contrat n'existe pas on renvoi un message d'erreur
            return Response({"error" : "Aucun contrat avec cette id n'existe."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e :
            return Response({"error" : str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get(self, request) : 
        if request.user.role != "superadmin" : 
            return Response({"error" : "Vous n'avez pas la permission de voir les contrats."}, status=status.HTTP_401_UNAUTHORIZED)
        
        try : 
            contrats = Contrat.objects.all()
            serializer = ListContratSerializer(contrats, many=True)
            return Response(serializer.data)
        except Contrat.DoesNotExist : 
            return Response({"error" : "Aucun contrat n'existe."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e :
            return Response({"error" : str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class EmployerListView(APIView) : 
    #On définit les permissions
    permission_classes = [IsAuthenticated]

    #On créer le code pour ajouter l'employer
    def post(self, request, contrat_id, shop_id) :
        
        try : 
            #On vérifie si l'utilisateur à la permission d'ajouter des employer
            if request.user.role != "superadmin" :
                return Response({"error" : "Vous n'avez pas la permission d'ajouter des employer."}, status=status.HTTP_401_UNAUTHORIZED)
            
            #On initialise le serializer
            serializer = AddEmployerSerializer(data=request.data)

            #On vérifie si le serializer est valide
            if not serializer.is_valid() :
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
            #On vérifie que le contrat existe
            try : 
                contrat = Contrat.objects.get(id=contrat_id)
            except Contrat.DoesNotExist:
                return Response({"error" : "Aucun contrat n'existe avec cette identifiant."}, status=status.HTTP_404_NOT_FOUND)
            
            #On vérifie que la magasin existe
            try : 
                shop = Magasin.objects.get(id=shop_id) 
            except Magasin.DoesNotExist :
                return Response({"error" : "Aucun magasin n'existe avec cette identifiant."}, status=status.HTTP_404_NOT_FOUND)
            #On récupère les données du serializer
            data = serializer.validated_data
            #On créé un nouvel utilisateur en lui donnant le role employer
            new_user = User.objects.create_user(
                username=data["username"],
                email=data["email"],
                last_name=data["last_name"],
                password="Password@1",
                role="employe",
                contrat=contrat,
                admin=request.user
            )
            #On lui assigne les magasins
            new_user.magasin.add(shop)
            #On récupère les donnée dans workingday
            working = data["working_day"]
            
            #On créer un nouvel object working_day
            WorkingDay.objects.create(
                user=new_user,
                working_day=working["working_day"],
                start_job=working["start_job"],
                end_job=working["end_job"]
            )
            #On retourne un message de succès
            return Response({"message" : "Employé créé avec succès."}, status=status.HTTP_201_CREATED)
        except Exception as e :
            return Response({"error" : str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    #On créé le code pour afficher les employes
    def get(self, request) :
        #On vérifie si le role de l'utilisateur est superadmin
        if request.user.role != "superadmin" :
            return Response({"error" : "Vous n'avez pas la permission de voir tous les employes."}, status=status.HTTP_401_UNAUTHORIZED)
        
        try : 
            #On récupère les employes lier à l'admin
            employes = User.objects.filter(admin=request.user)
            serializer = ListEmployerSerializer(employes, many=True)
            return Response(serializer.data)
        except Exception as e :
            return Response({"error" : str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    


    def delete(self, request, employer_id) :
        #On vérifie si l'utilisateur à le rôle admin
        if request.user.role != "superadmin" : 
            return Response({"error" : "Vous n'avez pas la permission de supprimer des employes."}, status=status.HTTP_401_UNAUTHORIZED)
        
        try :
            #On récupère l'employer par sont id
            employer = User.objects.get(id=employer_id)
            employer.delete() #On le supprime et on envoi un message de succèss
            return Response({"message" : "L'employe à bien été supprimer avec succès."}, status=status.HTTP_200_OK)
        except User.DoesNotExist : 
            return Response({"error" : "Aucun employer n'existe avec cette id."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error" : str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
         

class EmployerDetailAPIView(APIView) :
    def get(self, request, pk) :
        if request.user.role != "superadmin" : 
            return Response({"error" : "Vous n'avez pas la permission de modifier un employer."}, status=status.HTTP_401_UNAUTHORIZED)
        try :
            #On récupère l'employer grace à sont id 
            employe = User.objects.get(pk=pk, admin=request.user)
            serializer = DetailEmployerSerializer(employe)
            
            #On récupère le magasin lier à l'employer
            magasins = Magasin.objects.filter(employes=employe)
            #On récupère le contrat lier à l'employer
            contrat = employe.contrat

            magasins_data = ListShopSerializer(magasins, many=True).data
            contrats_data = ListContratSerializer(contrat).data if contrat else None
            
            data = serializer.data
            data["magasins"] = magasins_data
            data["contrats"] = contrats_data
            return Response(data)
        except User.DoesNotExist : 
            return Response({"error" : "Employé introuvable."}, status=status.HTTP_404_NOT_FOUND)
    
    def patch(self, request, employer_id):
        #On vérifie si l'utilisateur à le rôle superadmin
        if request.user.role != "superadmin":
         return Response({"error": "Vous n'avez pas la permission de modifier un employé."},
                            status=status.HTTP_401_UNAUTHORIZED)
    
        try:
            #On récupère l'employer
            employe = User.objects.get(id=employer_id, admin=request.user)
        except User.DoesNotExist:
            return Response({"error": "Employé introuvable."}, status=status.HTTP_404_NOT_FOUND)
        #On initialize le serializer avec les données
        serializer = AddEmployerSerializer(employe, data=request.data, partial=True)
        #On vérifie si le serializer est valide 
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        #On sauvegarde les données 
        serializer.save()

        # Accès aux données liées (facultatif ici)
        magasins = employe.magasin.all()
        contrat = employe.contrat

        return Response({
            "employe": serializer.data,
            "magasins": ShopSerializer(magasins, many=True).data,
            "contrat": ContratSerializer(contrat).data if contrat else None
        })
class VacationAPIVew(APIView) :
    #On fait la demande de vacance
    def post(self, request, employer_id) : 
        #On vérifie si les données sont présent dans la requête
        if not request.data : 
            return Response({"error" : "Aucune données n'a été fournis."}, status=status.HTTP_400_BAD_REQUEST)
        
        try :
            #On vérifie si l'utilisateur existe
            user = User.objects.get(id=employer_id)
        except User.DoesNotExist :
            return Response({"error" : "Utilisateur introuvable."}, status=status.HTTP_404_NOT_FOUND)
        #On vérifie si le serializer est valide
        serializer = CheckVacationSerializer(data=request.data)
        
        #Si le serializer est valide on ajoute le status  "pending"
        if serializer.is_valid() :
            #On créer un nouvel objet Vacation
            Vacation.objects.create(
                user=user,
                start_day = serializer.validated_data['start_day'],
                end_day = serializer.validated_data['end_day'],
                status="pending"
            )
            return Response({"message" : "Vacance en attente de validation."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    #On récupère tout les demandes de vacances
    def get(self,request) : 
        #On vérifie le role de l'utilisateur 
        if request.user.role != "superadmin" :
            return Response({"error" : "Vous n'avez pas la permission de voir les demande de vacances."}, status=status.HTTP_401_UNAUTHORIZED)

        try : 
            vacance = Vacation.objects.select_related('user').all()
            serializer = VacationSerializer(vacance, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e :
            return Response({"error" : str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def patch(self, request, employer_id, vacation_id):
        if request.user.role != "superadmin":
            return Response({"error": "Vous n'avez pas la permission d'accepter ou de refuser les demandes de vacances."}, status=status.HTTP_401_UNAUTHORIZED)

        data = request.data
        if data.get("status") not in ["accepted", "rejected"]:
            return Response({"error": "Le statut doit être 'accepted' ou 'rejected'."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            vacance = Vacation.objects.get(id=vacation_id, user_id=employer_id)
            vacance.status = data["status"]
            vacance.save()
            return Response({"message": f"La demande de vacances a été marquée comme {data['status']}."}, status=status.HTTP_200_OK)

        except Vacation.DoesNotExist:
            return Response({"error": "Aucune demande de vacances ne correspond à cet identifiant et cet utilisateur."}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

                
            

        



        
        

        



            

             

    
            
            
                

    


        
    


   
    
        
 



                
            
    
    

