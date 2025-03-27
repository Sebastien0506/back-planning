from rest_framework import serializers
# from .models import User, Employes, Travail
from django.contrib.auth.hashers import make_password, check_password
import html
from datetime import time, datetime
from django.contrib.auth import get_user_model

User = get_user_model()
    
# class TravailSerializer(serializers.ModelSerializer) : 
#     class Meta :
#         model = Travail
#         fields = ['start_job', 'end_job', 'work_day']

#     def clean_input(self, value) : 
#             ##
#             # On échappe les caractères spéciaux##
#         if isinstance(value, list) :
#             return [html.escape(str(item)) for item in value]
#         elif isinstance(value, str) :
#             return html.escape(value)
#         return value
        
#     def valide_start_job(self, value) :
#         clean_value = self.clean_input(value)
            
#         if isinstance(clean_value, str) :
#             try :
#                 clean_value = datetime.strptime(clean_value, "%H:%M").time()
#             except ValueError : 
#                 raise serializers.ValidationError("L'heure de début doit être dans le format HH:MM (ex: 12:00)")
#         elif not isinstance(clean_value, time) :
#             raise serializers.ValidationError("L'heure de début doit être un objet de type time.")
#         return clean_value
        
        
#     def valide_end_job(self, value) : 
#         cleaned_value = self.clean_input(value)
#         start_job = self.valide_start_job(cleaned_value)

#         if isinstance(cleaned_value, str) : 
#             try : 
#                 cleaned_value = datetime.strptime(cleaned_value, "%H:%M").time()
#             except ValueError : 
#                 raise serializers.ValidationError("L'heure de fin doit être dans le format HH:MM (ex: 21:00)")
#         elif not isinstance(cleaned_value, time) :
#             raise serializers.ValidationError("L'heure de fin doit être un objet de type time.")
            
#         if cleaned_value < start_job : 
#             raise serializers.ValidationError("L'heure de fin ne doit pas être avant l'heure de début")
#         return cleaned_value

#     def validate_work_day(self, value) :
#         cleaned_value = self.clean_input(value)

#         if not isinstance(cleaned_value, list) : 
#             raise serializers.ValidationError("Les données doivent être sous forme de liste.")

#         if cleaned_value is None :
#             raise serializers.ValidationError("Au moin un jours de travail doit être renseigner.")
         
#         validated_day = []
#         for day in cleaned_value :
#             if not isinstance(day, str) or not day.isalpha() :
#                 raise serializers.ValidationError(f"Le jour '{day}' contient de caractères non valides. Seules les lettres sont autorisées. ")
#             validated_day.append(day)
        
#         return validated_day
            
    
# class EmployeTravailSerializer(serializers.Serializer) : 
#     employe = EmployesSerializer()
#     travail = TravailSerializer()

#     def create(self, validated_data) : 
#         employe_data = validated_data.pop("employe")
#         travail_data = validated_data.pop("travail")

#         employe = Employes.objects.create(**employe_data)

#         Travail.objects.create(employe=employe, **travail_data)

#         return {"employe": employe, "travail" : travail_data}

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
    





# #Sérializeur utilisé lors de la connexion.
# class LoginSerializer(serializers.Serializer) :
#     #On récupère l'email et le mot de passe. 
#     email = serializers.EmailField()
#     password = serializers.CharField(write_only=True)

#     #On échappe les caractères spéciaux.
#     def clean_input(selft, value) : 
#         #On échappe les caractères spéciaux.
#         return html.escape(value)
    
#     #On vérifie que l'email est correct.
#     def validate_email(self, value) : 
#         cleaned_value = self.clean_input(value)
        
#         #On vérifie que @ n'est pas présent plusieur fois
#         if cleaned_value.count("@") != 1 :
#             raise serializers.ValidationError("L'email doit contenir un seul '@'.")
        
#         #On vérifie qu'il n'y est pas de caractère spéciaux à par ceux qui sont accepter
#         if not all(char.isalnum() or char in ["@", ".", "-", "_"] for char in cleaned_value):
#             raise serializers.ValidationError("L'email contient des caractères invalides.")
        
        
#         #On vérifier qu'il y est bien un @, un point et un nom de domaine valide.
#         if "@" not in cleaned_value or "." not in cleaned_value : 
#             raise serializers.ValidationError("L'email doit contenir un '@' et un nom de domaine valide.")
        
#         return cleaned_value
    
#     def validate_password(self, value) : 
        
        

#         # Définition des caractères spéciaux autorisés
#         special_chars = {"@", "$", "!", "%", "*", "?", "&"}

#         # Vérification de la longueur minimale
#         if len(value) < 8:
#             raise serializers.ValidationError("Le mot de passe doit contenir au moins 8 caractères.")

#         # Vérification de la présence d'au moins une majuscule
#         if not any(char.isupper() for char in value):
#             raise serializers.ValidationError("Le mot de passe doit contenir au moins une lettre majuscule.")

#         # Vérification de la présence d'au moins une minuscule
#         if not any(char.islower() for char in value):
#             raise serializers.ValidationError("Le mot de passe doit contenir au moins une lettre minuscule.")

#         # Vérification de la présence d'au moins un chiffre
#         if not any(char.isdigit() for char in value):
#             raise serializers.ValidationError("Le mot de passe doit contenir au moins un chiffre.")

#         # Vérification de la présence d'au moins un caractère spécial autorisé
#         if not any(char in special_chars for char in value):
#             raise serializers.ValidationError("Le mot de passe doit contenir au moins un caractère spécial (@, $, !, %, *, ?, &).")

#         # Vérification que seuls les caractères valides sont utilisés
#         if not all(char.isalnum() or char in special_chars for char in value):
#             raise serializers.ValidationError("Le mot de passe contient des caractères spéciaux non autorisés.")

#         return value 

        
    

