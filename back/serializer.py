from rest_framework import serializers
from django.contrib.auth.hashers import make_password, check_password
import html
from datetime import time, datetime
from django.contrib.auth import get_user_model
from back.models import Magasin, Contrat, WorkingDay

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
    class Meta :
        model = WorkingDay
        fields = ["working_day", "start_job", "end_job"]
    
    def validate_working_day(self, value) :
        if not value : 
            raise serializers.ValidationError("Le tableau ne doit pas être vide.")
        cleaned_days = []

        for day in value : 
            escape_day = html.escape(day)

            if not escape_day.isalpha():
                raise serializers.ValidationError(f"Le jour '{escape_day}' doit contenir uniquement des lettres.")
            cleaned_days.append(escape_day)
        return cleaned_days
    
    def validate(self, data) : 
        start_job = data.get('start_job')
        end_job = data.get('end_job')

        if not isinstance(start_job, time) or not isinstance(end_job, time) :
            raise serializers.ValidationError("l'heure de début et l'heure de fin doivent être valides.")
        
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
        fields = ['name']
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
        fields = ["name"]

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
    
        

         

        

    
    

