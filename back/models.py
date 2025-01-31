from django.db import models
from django.contrib.auth.hashers import make_password, check_password

class Administrateur(models.Model):
    name = models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    email = models.EmailField(max_length=50, unique=True)  # Email unique
    password = models.CharField(max_length=128)  # Stocke le hash du mot de passe

    