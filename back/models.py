from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ValidationError
from django.contrib.postgres.fields import ArrayField
from django.contrib.auth.models import AbstractUser
import datetime


class User(AbstractUser) : 
    username = models.CharField(max_length=50, unique=False)
    email = models.EmailField(unique=True)
    magasin = models.ManyToManyField('Magasin', related_name='employes', blank=True)
    
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
    contrat = models.ForeignKey(
        'Contrat',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='users'
    )
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

class Magasin(models.Model) : 
    shop_name = models.CharField(max_length=50, unique=True)
    created_by = models.ManyToManyField(User, related_name='magasins_crees')

class Contrat(models.Model) : 
    contrat_name = models.CharField(max_length=10, unique=True)

class WorkingDay(models.Model) : 
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="working_day")
    working_day = ArrayField(
        models.CharField(max_length=10), size=7, null=True
    )
    start_job = models.TimeField(null=True, auto_now=False, auto_now_add=False)
    end_job = models.TimeField(null=True, auto_now=False, auto_now_add=False)

class Vacation(models.Model) :
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="vacations")
    start_day = models.DateField()
    end_day = models.DateField()
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    






            

