from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ValidationError
from django.contrib.postgres.fields import ArrayField
from django.contrib.auth.models import AbstractUser


class User(AbstractUser) : 
    username = models.CharField(max_length=50, unique=False)
    email = models.EmailField(unique=True)
    ROLE_CHOICES = (
        ('superadmin', 'Super Administrateur'),
        ('admin', 'Administrateur'),
        ('employe', 'Employe')
    )
    role = models.CharField(max_length=15, choices=ROLE_CHOICES)
    admin = models.ForeignKey(
        'self',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='employes'
    )
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

class Magasin(models.Model) : 
    name = models.CharField(max_length=50, unique=True)
    created_by = models.ManyToManyField(User)





            

