from rest_framework import serializers
from .models import Administrateur
from django.contrib.auth.hashers import make_password, check_password
import html

class AdministrateurSerializer(serializers.ModelSerializer):
    class Meta:
        model = Administrateur
        fields = ['username', 'lastname', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def clean_input(self, value):
        """
        Échappe les caractères spéciaux pour éviter les attaques XSS.
        """
        return html.escape(value)

    def validate_username(self, value):
        """
        Nettoie et valide le champ 'username'.
        """
        cleaned_value = self.clean_input(value)
        if not all(char.isalnum() or char in ["-", "'"] for char in cleaned_value):
            raise serializers.ValidationError("Le nom d'utilisateur ne doit contenir que des lettres et des chiffres.")
        return cleaned_value

    def validate_lastname(self, value):
        """
        Nettoie et valide le champ 'lastname'.
        """
        cleaned_value = ''.join( e for e in value if e.isalpha() or e.isspace() or e == "-") 
        if not cleaned_value.strip():  # Autorise les espaces
            raise serializers.ValidationError("Le prénom ne doit contenir que des lettres.")
        return cleaned_value

    def validate_email(self, value):
        """
        Nettoie et valide le champ 'email'.
        """
        cleaned_value = self.clean_input(value)
        if "@" not in cleaned_value:
            raise serializers.ValidationError("Adresse e-mail invalide.")
        return cleaned_value

    def validate_password(self, value):
        """
        Nettoie et valide le mot de passe.
        """
        cleaned_value = self.clean_input(value)
        if len(cleaned_value) < 8:
            raise serializers.ValidationError("Le mot de passe doit contenir au moins 8 caractères.")
        return cleaned_value

    def create(self, validated_data):
        """
        Hache le mot de passe avant de sauvegarder l'administrateur.
        """
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)

#Sérializeur utilisé lors de la connexion.
class loginSerializeur(serializers.Serializer) :
    #On récupère l'email et le mot de passe. 
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    #On échappe les caractères spéciaux.
    def clean_input(selft, value) : 
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
        
        cleaned_value = self.clean_input(value)

        # Définition des caractères spéciaux autorisés
        special_chars = {"@", "$", "!", "%", "*", "?", "&"}

        # Vérification de la longueur minimale
        if len(cleaned_value) < 8:
            raise serializers.ValidationError("Le mot de passe doit contenir au moins 8 caractères.")

        # Vérification de la présence d'au moins une majuscule
        if not any(char.isupper() for char in cleaned_value):
            raise serializers.ValidationError("Le mot de passe doit contenir au moins une lettre majuscule.")

        # Vérification de la présence d'au moins une minuscule
        if not any(char.islower() for char in cleaned_value):
            raise serializers.ValidationError("Le mot de passe doit contenir au moins une lettre minuscule.")

        # Vérification de la présence d'au moins un chiffre
        if not any(char.isdigit() for char in cleaned_value):
            raise serializers.ValidationError("Le mot de passe doit contenir au moins un chiffre.")

        # Vérification de la présence d'au moins un caractère spécial autorisé
        if not any(char in special_chars for char in cleaned_value):
            raise serializers.ValidationError("Le mot de passe doit contenir au moins un caractère spécial (@, $, !, %, *, ?, &).")

        # Vérification que seuls les caractères valides sont utilisés
        if not all(char.isalnum() or char in special_chars for char in cleaned_value):
            raise serializers.ValidationError("Le mot de passe contient des caractères spéciaux non autorisés.")

        return cleaned_value 

        
    

