from django.test import TestCase
from django.contrib.auth.hashers import identify_hasher
from back.serializer import AdministrateurSerializer, LoginSerializer
from back.utils import generate_jwt, decoded_jwt, expired_token


class GenerateJwtTest(TestCase) : 
    def test_generate_jwt(self) : 
        encoded_jwt = generate_jwt()
        print("JWT:", encoded_jwt)
    
    def test_decoded_jwt(self) : 
        encoded_jwt = expired_token()
        access_token = encoded_jwt["access_token"]

        decoded = decoded_jwt(access_token)
        print("Payload décodé:", decoded )

        self.assertIn("some", decoded)
        self.assertEqual(decoded["some"], "payload")
        self.assertIn("exp", decoded)

# class AdministrateurSerializerTest(TestCase):
#     """Tests pour le sérialiseur AdministrateurSerializer"""

#     def test_valid_name(self):
#         """Test avec des données valides"""
#         data = {
#             "username": "adminTest",
#             "lastname": "Dupont",
#             "email": "admin@example.com",
#             "password": "SecurePass@123"
#         }
        
#         serializer = AdministrateurSerializer(data=data)

#         # Vérifier que le sérialiseur est valide
#         self.assertTrue(serializer.is_valid(), serializer.errors)

        

#     def test_invalid_name(self):
#         """Test avec un nom invalide"""
#         data = {
#             "username": "adminTest@1",
#             "lastname": "Dupont",
#             "email": "invalid-email",
#             "password": "SecurePass123"
#         }
#         serializer = AdministrateurSerializer(data=data)
        
#         # Vérifier que le sérialiseur est invalide
#         self.assertFalse(serializer.is_valid())

#         # Vérifier que l'erreur concerne bien l'email
#         self.assertIn("username", serializer.errors)

#     def test_valide_email(self):
          
#          """Test que les scripts XSS sont bien échappés"""
        
#          data = {
#             "username": "Jean-Luc",
#             "lastname": "Dupont",
#             "email": "user@example.com",
#             "password": "Password@123"
#             }
#          serializer = AdministrateurSerializer(data=data)

#          self.assertTrue(serializer.is_valid(), serializer.errors)

#     def test_invalid_email(self) : 
#         data = {
#             "username" : "Jean",
#             "lastname" : "Dupont",
#             "email" : "jeandupont.gmail.com",
#             "password" : "Password@1"
#         }

#         serializer = AdministrateurSerializer(data=data)
#         self.assertFalse(serializer.is_valid(), serializer.errors)
    
#     def test_valid_password(self) : 
#         data = {
#             "username" : "Jean",
#             "lastname" : "Dupont",
#             "email" : "jeandupont@gmail.com",
#             "password" : "Password@1"
#         }
#         serializer = AdministrateurSerializer(data=data)
#         self.assertTrue(serializer.is_valid(), serializer.errors)
 
#         # ✅ Exécuter create() et vérifier le mot de passe haché
#         saved_admin = serializer.save()

        
#         print("Mot de passe après validation :", saved_admin.password)

#     def test_invalid_password(self) : 
#         data = {
#             "username" : "Jean",
#             "lastname" : "Dupont",
#             "email" : "jeandupont@gmail.com",
#             "password" : "password"
#         }
#         serializer = AdministrateurSerializer(data=data)

#         self.assertFalse(serializer.is_valid(), serializer.errors)


        

    # Vérifier que les valeurs sont bien échappées
        
        #  validated_data = serializer.validated_data
        
        #  print("Username après nettoyage :", validated_data["username"])  # DEBUG
        
        #  print("Lastname après nettoyage :", validated_data["lastname"])  # DEBUG

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

        

        
