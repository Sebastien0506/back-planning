from rest_framework import serializers
from django.contrib.auth.hashers import make_password, check_password
import html
from datetime import time, datetime
from django.contrib.auth import get_user_model
from back.models import Magasin, Contrat, WorkingDay, Vacation

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'last_name', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
            'role': {'read_only': True},
            'admin': {'read_only': True},
        }

    def clean_input(self, value):
        return html.escape(value)

    def validate_username(self, value):
        cleaned_value = self.clean_input(value)
        if not all(char.isalpha() or char == "-" for char in cleaned_value):
            raise serializers.ValidationError("Le nom d'utilisateur ne doit contenir que des lettres.")
        return cleaned_value

    def validate_last_name(self, value):
        cleaned_value = self.clean_input(value)
        if not all(char.isalpha() or char in ["-", " "] for char in cleaned_value):
            raise serializers.ValidationError("Le prénom ne doit contenir que des lettres ou des tirets.")
        return cleaned_value

    def validate_email(self, value):
        cleaned_value = self.clean_input(value)
        if cleaned_value.count("@") != 1 or "." not in cleaned_value:
            raise serializers.ValidationError("Adresse e-mail invalide.")
        if not all(char.isalnum() or char in ["@", ".", "-", "_"] for char in cleaned_value):
            raise serializers.ValidationError("L'e-mail contient des caractères non valides.")
        return cleaned_value
    
    def validate_password(self, value):
        """
        Nettoie et valide le mot de passe.
        """
        
        special_chars = {"@", "$", "!", "%", "*", "?", "&"}
        #On vérifie que le mot de passe est au moin 8 caractères.
        if len(value) < 8:
            raise serializers.ValidationError("Le mot de passe doit contenir au moins 8 caractères.")
        
        #On vérifie que le mot de passe contient au moin une majscule.
        if not any(char.isupper() for char in value) : 
            raise serializers.ValidationError("Le mot de passe doit contenir au moin une majscule.")
        
        #On vérifie que le mot de passe contient au moin une minuscule.
        if not any(char.islower() for char in value) : 
            raise serializers.ValidationError("Le mot de passe doit contenir au moin une minuscule.")
        
        #On vérifie que le mot de passe contient au moin un chiffre.
        if not any(char.isdigit() for char in value) : 
            raise serializers.ValidationError("Le mot de passe doit contenir au moin un chiffre.")
        
        # Vérification de la présence d'au moins un caractère spécial autorisé
        if not any(char in special_chars for char in value):
            raise serializers.ValidationError("Le mot de passe doit contenir au moins un caractère spécial (@, $, !, %, *, ?, &).")

        # Vérification que seuls les caractères valides sont utilisés
        if not all(char.isalnum() or char in special_chars for char in value):
            raise serializers.ValidationError("Le mot de passe contient des caractères spéciaux non autorisés.")
        
        return value


    def create(self, validated_data):
        request = self.context.get("request")

        # ⚙️ Si l'utilisateur est connecté (admin), on crée un employé
        if request and request.user and request.user.is_authenticated:
            validated_data["role"] = "employe"
            validated_data["admin"] = request.user

        # ⚙️ Sinon (première inscription) → c’est un admin
        else:
            validated_data["role"] = "admin"

        user = User.objects.create_user(**validated_data)
        return user

#Sérializer pour vérifier les jours de travail    
class WorkingDaySerializer(serializers.ModelSerializer) : 
    working_day = serializers.ListField(
        child=serializers.CharField(),
        allow_empty=True,
        required=False
    )
    class Meta :
        model = WorkingDay
        fields = ["working_day", "start_job", "end_job"]
    #Validation des jours de travail
    def validate_working_day(self, value) :
        
        cleaned_days = []
        #Pour chaque jour on échappe tous les caractères
        for day in value : 
            escape_day = html.escape(day)
            #On vérifie si le jour de travail contient uniquement des lettres
            if not escape_day.isalpha():
                raise serializers.ValidationError(f"Le jour '{escape_day}' doit contenir uniquement des lettres.")
            cleaned_days.append(escape_day)
        return cleaned_days
    
    def validate(self, data) : 
        #On récupère l'heure de debut et de fin
        start_job = data.get('start_job')
        end_job = data.get('end_job')
        #On vérifie si l'heure de fin et de début sont bien de type time
        if not isinstance(start_job, time) or not isinstance(end_job, time) :
            raise serializers.ValidationError("l'heure de début et l'heure de fin doivent être valides.")
        #On vérifie si l'heure de fin n'est pas avant l'heure de début
        if start_job >= end_job :
            raise serializers.ValidationError("L'heure de début doit être avant l'heure de fin.")
        return data
    
# #Sérializeur utilisé lors de la connexion.
class LoginSerializer(serializers.Serializer) :
    #On récupère l'email et le mot de passe. 
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    #On échappe les caractères spéciaux.
    def clean_input(self, value) : 
        #On échappe les caractères spéciaux.
        return html.escape(value)
    
    #On vérifie que l'email est correct.
    def validate_email(self, value) : 
        cleaned_value = self.clean_input(value)
        
        #On vérifie que @ n'est pas présent plusieur fois
        if cleaned_value.count("@") != 1 :
            raise serializers.ValidationError("L'email doit contenir un seul '@'.")
        
        #On vérifie qu'il n'y est pas de caractère spéciaux à par ceux qui sont accepter
        if not all(char.isalnum() or char in ["@", ".", "-", "_"] for char in cleaned_value):
            raise serializers.ValidationError("L'email contient des caractères invalides.")
        
        
        #On vérifier qu'il y est bien un @, un point et un nom de domaine valide.
        if "@" not in cleaned_value or "." not in cleaned_value : 
            raise serializers.ValidationError("L'email doit contenir un '@' et un nom de domaine valide.")
        
        return cleaned_value
    
    def validate_password(self, value) : 
        
        # Définition des caractères spéciaux autorisés
        special_chars = {"@", "$", "!", "%", "*", "?", "&"}

        # Vérification de la longueur minimale
        if len(value) < 8:
            raise serializers.ValidationError("Le mot de passe doit contenir au moins 8 caractères.")

        # Vérification de la présence d'au moins une majuscule
        if not any(char.isupper() for char in value):
            raise serializers.ValidationError("Le mot de passe doit contenir au moins une lettre majuscule.")

        # Vérification de la présence d'au moins une minuscule
        if not any(char.islower() for char in value):
            raise serializers.ValidationError("Le mot de passe doit contenir au moins une lettre minuscule.")

        # Vérification de la présence d'au moins un chiffre
        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError("Le mot de passe doit contenir au moins un chiffre.")

        # Vérification de la présence d'au moins un caractère spécial autorisé
        if not any(char in special_chars for char in value):
            raise serializers.ValidationError("Le mot de passe doit contenir au moins un caractère spécial (@, $, !, %, *, ?, &).")

        # Vérification que seuls les caractères valides sont utilisés
        if not all(char.isalnum() or char in special_chars for char in value):
            raise serializers.ValidationError("Le mot de passe contient des caractères spéciaux non autorisés.")

        return value 

class ShopSerializer(serializers.ModelSerializer) : 
    class Meta:
        model = Magasin
        fields = ['shop_name']
    # Échappe tous les caractès html
    def clean_input(self, value) : 
        return html.escape(value)
    
    def validate_name(self, value) :
        cleaned_value = self.clean_input(value)
        #Supprime les espaces au début et à la fin
        cleaned_value = cleaned_value.strip()
        # Vérifie si le champ contient au moin une lettre 
        if len(cleaned_value) < 1 : 
            raise serializers.ValidationError("Le champ du formulaire doit contenir au moins une lettre.")
        #Vérifie si les caractères sont des caractères autorisé
        if not cleaned_value.isalnum() : 
            raise serializers.ValidationError("Données incorrect. Seules les lettres et les chiffres sont autorisés.")
        
        return cleaned_value
    
class ContratSerializer(serializers.ModelSerializer) : 
    class Meta : 
        model = Contrat  
        fields = ["contrat_name"]

    def clean_input(self, value) : 
        return html.escape(value)
    
    def validate_name(self, value) : 
        cleaned_value = self.clean_input(value)
        cleaned_value = cleaned_value.strip()

        if not isinstance(cleaned_value, str) : 
            raise serializers.ValidationError("Lee données ne sont pas une chaine de caractère.")
        
        if len(cleaned_value) < 1 :
            raise serializers.ValidationError("Les données doivent contenir au moin un caractère.")
        
        if not cleaned_value.isalpha() : 
            raise serializers.ValidationError("Les données ne doivent contenir que des lettres.")
        
        return cleaned_value
    
        
class AddEmployerSerializer(serializers.ModelSerializer) :
    working_day = WorkingDaySerializer(required=False)
    magasin = serializers.PrimaryKeyRelatedField(queryset=Magasin.objects.all(), many=True)
    contrat = serializers.PrimaryKeyRelatedField(queryset=Contrat.objects.all())
    password = serializers.CharField(write_only=True, required=False, allow_blank=True)

    class Meta : 
        model = User
        fields = ["username", "last_name", "email","password", "working_day", "contrat", "magasin"]
    #On nettoie les champs
    def clean_input(self, value) : 
        return html.escape(value)
    
    #On vérifie le champ username
    def validate_username(self, value) :
        cleaned_value = self.clean_input(value).strip()

        if len(cleaned_value) < 1 :
            raise serializers.ValidationError("Le champ 'username' doit contenir au moin une lettre.")
        
        if not all(char.isalpha() or char == "-" for char in cleaned_value):
            raise serializers.ValidationError("Le nom d'utilisateur ne doit contenir que des lettres.")
        return cleaned_value
    
    #On vérifie le champ last_name
    def validate_last_name(self, value):
        cleaned_value = self.clean_input(value).strip()

        #On vérifie la longueur du champ
        if len(cleaned_value) < 1 :
            raise serializers.ValidationError("Le champ 'last_name' doit contenir au moin une lettre.")
        
        #On vérifie que cleaned_value ne contient que des lettres.
        if not all(char.isalpha() or char == "-" for char in cleaned_value):
            raise serializers.ValidationError("Le nom d'utilisateur ne doit contenir que des lettres.")
        return cleaned_value
    
    #On vérifie l'email
    def validate_email(self, value) :
        #On nettoie la valeur et on supprime les espaces au début et à la fin du champ
        cleaned_value = self.clean_input(value).strip()
        domain_accepted = ["gmail.com", "yahoo.com", "orange.fr"]
        #on vérifie la longueur du champ
        if len(cleaned_value) < 1 :
            raise serializers.ValidationError("Le champ 'email' ne doit pas être vide.")

        #On vérifie si le champ contient un @
        if cleaned_value.count("@") != 1 :
            raise serializers.ValidationError("L'email doit contenir un seul '@'.")
        #On récupère le nom de domaine
        local_part, domaine_part = cleaned_value.split("@")

        #On vérifie si le nom de domain est valide
        if domaine_part not in domain_accepted : 
            raise serializers.ValidationError(f"Le nom de domain {domaine_part}, n'est pas autorisé.")

        #On vérifie si tous les caractères sont valide
        if not all(char.isalnum() or char in ["-", "_", "."] for char in local_part) : 
            raise serializers.ValidationError("La partie avant le '@' est invalide.")
        return cleaned_value
    
    def update(self, instance, validated_data):
        working_day_data = validated_data.pop('working_day', None)
        magasin_data = validated_data.pop('magasin', None)

        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        if magasin_data is not None:
            instance.magasin.set(magasin_data)

        if working_day_data:
            # Supprimer l'ancien
            instance.working_day.delete()
            # Créer le nouveau
            WorkingDay.objects.create(user=instance, **working_day_data)

        return instance

#POUR SERIALIZER LES DONNÉES

class ListContratSerializer(serializers.ModelSerializer) :
    #Serializer pour récuperer tous les contrats
    class Meta : 
        model = Contrat
        fields = '__all__'

class ListEmployerSerializer(serializers.ModelSerializer) : 
    #Serializer pour récuperer tous les employes lier à un superadmin
    class Meta :
        model = User
        fields = ["id", "username", "last_name", "email"]
class ListShopSerializer(serializers.ModelSerializer) :
    class Meta : 
        model = Magasin
        fields = ["id", "shop_name"]

class ListWorkingDaySerializer(serializers.ModelSerializer) : 
    class Meta:
        model = WorkingDay
        fields = ['working_day', 'start_job', 'end_job', 'user']

class ListContratSerializer(serializers.ModelSerializer) :
    class Meta :
        model = Contrat
        fields = ["id", "contrat_name"]

class DetailEmployerSerializer(serializers.ModelSerializer) : 

    class Meta :
        model = User
        fields = ["username", "last_name", "email"]

class CheckVacationSerializer(serializers.ModelSerializer) : 
    class Meta :
        model = Vacation
        fields = ["start_day", "end_day"]

    def validate(self, data) :
        #On récupère le jour de debut
        start_day = data.get("start_day")
        #On récupère le jour de fi
        end_day = data.get("end_day")

        if not start_day :
            raise serializers.ValidationError("La date de début ne doit pas être vide.")
        if not end_day :
            raise serializers.ValidationError("La date de fin ne doit pas être vide.")
        
        if  start_day > end_day :
            raise serializers.ValidationError("La date de début doit être avant la date de fin.")
        
        return data
class VacationSerializer(serializers.ModelSerializer) :
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta : 
        model = Vacation
        fields = ['username', "start_day", "end_day", "status"]

        

         
         
        
        

    
    

