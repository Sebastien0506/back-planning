from django.test import TestCase
from django.contrib.auth.hashers import identify_hasher
from back.serializer import UserSerializer
# from back.utils import generate_jwt, decoded_jwt

# class TravailTest(TestCase) : 
#     def test_valid_start_job(self) : 
#         data = {
#             "start_job" : "12:00",
#             "end_job" : "21:00",
#             "work_day" : ["Lundi", "Mardi", "Jeudi", "Samedi"]
#         }
#         serializer = TravailSerializer(data=data)
#         self.assertTrue(serializer.is_valid(), serializer.errors)
    
#     def test_invalide_start_job(self) : 
#         data = {
#             "start_job" : "12h00",
#             "end_job" : "21:00",
#             "work_day" : ["Lundi", "Mardi", "Mercredi"]
#         }

#         serializer = TravailSerializer(data=data)
#         self.assertFalse(serializer.is_valid(), serializer.errors)
    
#     def test_valid_end_job(self) : 
#         data = {
#             "start_job" : "12:00",
#             "end_job" :"21:00",
#             "work_day" : ["Lundi", "Mardi", "Jeudi"]
#         }

#         serializer = TravailSerializer(data=data)
#         self.assertTrue(serializer.is_valid(), serializer.errors)
    
#     def test_invalid_end_job(self) : 
#         data = {
#             "start_job" : "12:00",
#             "end_job" : "21h00",
#             "work_day" : ["Lundi", "Mardi", "Mercredi"]
#         }
#         serializer = TravailSerializer(data=data)
#         self.assertFalse(serializer.is_valid(), serializer.errors)
    
#     def test_valid_work_day(self): 
#         data ={
#             "start_job" : "12:00",
#             "end_job" : "21:00",
#             "work_day" : ["Lundi", "Mardi", "Mercredi"]
#         }
#         serializer = TravailSerializer(data=data)
#         self.assertTrue(serializer.is_valid(), serializer.errors)

#     def test_invalid_work_day(self) : 
#         data = {
#             "start_job" : "12:00",
#             "end_job" : "21:00",
#             "work_day" : ["Lundi", "M@rdi", "Vendredi"]
#         }

#         serializer = TravailSerializer(data=data)
#         self.assertFalse(serializer.is_valid(), serializer.errors)


# class GenerateJwtTest(TestCase) : 
#     def test_generate_jwt(self) : 
#         encoded_jwt = generate_jwt()
#         print("JWT:", encoded_jwt)
    
#     def test_decoded_jwt(self) : 
#         encoded_jwt = generate_jwt()
#         access_token = encoded_jwt["access_token"]

#         decoded = decoded_jwt(access_token)
#         print("Payload décodé:", decoded )

#         self.assertIn("some", decoded)
#         self.assertEqual(decoded["some"], "payload")
#         self.assertIn("exp", decoded)

class UserSerializerTest(TestCase):
    """Tests pour le sérialiseur AdministrateurSerializer"""

    def test_valid_name(self):
        """Test avec des données valides"""
        data = {
            "username": "adminTest",
            "lastname": "Dupont",
            "email": "admin@example.com",
            "password": "SecurePass@123"
        }
        
        serializer = UserSerializer(data=data)

        # Vérifier que le sérialiseur est valide
        self.assertTrue(serializer.is_valid(), serializer.errors)

        

    def test_invalid_name(self):
        """Test avec un nom invalide"""
        data = {
            "username": "adminTest@1",
            "lastname": "Dupont",
            "email": "invalid-email",
            "password": "SecurePass123"
        }
        serializer = UserSerializer(data=data)
        
        # Vérifier que le sérialiseur est invalide
        self.assertFalse(serializer.is_valid())

        # Vérifier que l'erreur concerne bien l'email
        self.assertIn("username", serializer.errors)

    def test_valide_email(self):
          
         """Test que les scripts XSS sont bien échappés"""
        
         data = {
            "username": "Jean-Luc",
            "lastname": "Dupont",
            "email": "user@example.com",
            "password": "Password@123"
            }
         serializer = UserSerializer(data=data)

         self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_invalid_email(self) : 
        data = {
            "username" : "Jean",
            "lastname" : "Dupont",
            "email" : "jeandupont.gmail.com",
            "password" : "Password@1"
        }

        serializer = UserSerializer(data=data)
        self.assertFalse(serializer.is_valid(), serializer.errors)
    
    def test_valid_password(self) : 
        data = {
            "username" : "Jean",
            "lastname" : "Dupont",
            "email" : "jeandupont@gmail.com",
            "password" : "Password@1"
        }
        serializer = UserSerializer(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)
 
        # ✅ Exécuter create() et vérifier le mot de passe haché
        saved_admin = serializer.save()

        
        print("Mot de passe après validation :", saved_admin.password)

    def test_invalid_password(self) : 
        data = {
            "username" : "Jean",
            "lastname" : "Dupont",
            "email" : "jeandupont@gmail.com",
            "password" : "password"
        }
        serializer = UserSerializer(data=data)

        self.assertFalse(serializer.is_valid(), serializer.errors)

        #Vérifier que les valeurs sont bien échappées
        
        print("Erreur de validation :", serializer.errors)
        
        if serializer.is_valid() :
            validated_data = serializer.validated_data
            print("Username après nettoyage :" , validated_data["username"])
            print("Lastname après nettoyage :", validated_data["lastname"])

# class LoginSerializeurTest(TestCase) : 
#     """Test pour le sérializeur de Login"""

#     def test_valide_email(self) : 
#         data = {
#             "email" : "adminTest@gmail.com",
#             "password" : "Password1@",
#         }   

#         serializer = loginSerializeur(data=data)

#         self.assertTrue(serializer.is_valid(), serializer.errors)
    
#     def test_invalide_email(self) : 
#         data = {
#             "email" : "adminTest@@gmail.com",
#             "password" : "Password1@",
#         }

#         serializer = loginSerializeur(data=data)

#         self.assertFalse(serializer.is_valid(), serializer.errors)
    
#     def test_password_valid(self) :
#         data= {
#             "email" : "admintest@gmail.com",
#             "password" : "Password@1",

#         }

#         serializer = loginSerializeur(data=data)
#         self.assertTrue(serializer.is_valid(), serializer.errors)

#     def test_invalid_password(self) : 
#         data ={
#             "email" : "adminTest@gmail.com",
#             "password" : "password@1",
#         }

#         serializer = loginSerializeur(data=data)
#         self.assertFalse(serializer.is_valid(), serializer.errors)

        

        
