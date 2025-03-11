from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ValidationError


class Administrateur(models.Model):
    username = models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    email = models.EmailField(max_length=50, unique=True)  # Email unique
    password = models.CharField(max_length=128)  # Stocke le hash du mot de passe
    
    
    

class Employes(models.Model) : 
    username = models.CharField(max_length=50)
    lastname = models.CharField(max_length=50)
    email = models.EmailField(max_length=50, unique=True) 
    password = models.CharField(max_length=128)
    #On ajoute la relation ManyToMany entre les entité Employes et Administrateur
    administrateurs = models.ManyToManyField(Administrateur)

class Magasin(models.Model) : 
    name = models.CharField(max_length=50)
    #On ajoute la relation ManyToMany entre les entité Magasin et Administrateur
    administrateurs = models.ManyToManyField(Administrateur)
    #On ajoute la relation entre les entité Magasin et Employes
    employes = models.ManyToManyField(Employes)
     
class Contrats(models.Model) : 
    type_de_contrat = models.CharField(max_length=50)
    #On ajoute la relation entre les entités Contrats et Employes
    employes = models.ForeignKey(Employes, on_delete=models.CASCADE, null=True, blank=True)

class Vacances(models.Model) : 
    start_date = models.DateTimeField(null=False)
    end_date = models.DateTimeField(null=False)

    def clean(self):
        if self.end_date <= self.start_date :
            raise ValidationError("La date de fin doit être postérieur à la date de début.")

class Travail(models.Model) : 
    start_job = models.TimeField()
    end_job = models.TimeField()

    def clean(self) : 
        if self.end_job <= self.start_job : 
            raise ValidationError("L'heure de fin doit être postérieure à l'heure de début.")

class Planning(models.Model) : 
    start_planning = models.DateField()
    end_planning = models.DateField()
    employes = models.ManyToManyField(Employes)


            

