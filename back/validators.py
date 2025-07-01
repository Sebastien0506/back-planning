from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _ 

class CustomPasswordValidator:
    #Permet de vérifier que le mot de passe ne contient pas des caractères non autorisé.
    def validate(self, password, user=None) :
        allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%")
        if not set(password).issubset(allowed_chars) :
            raise ValidationError(
                _("Le mot de passe contient des caractères non autorisée."),
                code="invalid_password",
            )
    
    def get_help_text(self) :
        return("Votre mot de passe ne peut contenir que des lettres, des chiffres et les caractères @, #, $, %.")