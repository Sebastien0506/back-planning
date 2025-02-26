from rest_framework import serializers
from .models import Administrateur
from django.contrib.auth.hashers import make_password
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
