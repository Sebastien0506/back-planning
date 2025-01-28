from django.db import models
from django.contrib.auth.hashers import make_password, check_password

class Administrateur(models.Model):
    name = models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    email = models.EmailField(max_length=50, unique=True)  # Email unique
    password = models.CharField(max_length=128)  # Stocke le hash du mot de passe

    def set_password(self, raw_password):
        """
        Hache le mot de passe brut et le stocke dans le champ `password`.
        """
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        """
        Vérifie si le mot de passe brut correspond au hash enregistré.
        """
        return check_password(raw_password, self.password)