from django.test import TestCase
from django.contrib.auth.hashers import identify_hasher
from back.serializer import UserSerializer, ShopSerializer
# from back.utils import generate_jwt, decoded_jwt

#TEST VALIDE
# class UserSerializerTest(TestCase):
#     """Tests pour le sérialiseur AdministrateurSerializer"""

#     def test_valid_name(self):
#         """Test avec des données valides"""
#         data = {
#             "username": "adminTest",
#             "lastname": "Dupont",
#             "email": "admin@example.com",
#             "password": "SecurePass@123"
#         }
        
#         serializer = UserSerializer(data=data)

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
#         serializer = UserSerializer(data=data)
        
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
#          serializer = UserSerializer(data=data)

#          self.assertTrue(serializer.is_valid(), serializer.errors)

#     def test_invalid_email(self) : 
#         data = {
#             "username" : "Jean",
#             "lastname" : "Dupont",
#             "email" : "jeandupont.gmail.com",
#             "password" : "Password@1"
#         }

#         serializer = UserSerializer(data=data)
#         self.assertFalse(serializer.is_valid(), serializer.errors)
    
#     def test_valid_password(self) : 
#         data = {
#             "username" : "Jean",
#             "lastname" : "Dupont",
#             "email" : "jeandupont@gmail.com",
#             "password" : "Password@1"
#         }
#         serializer = UserSerializer(data=data)
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
#         serializer = UserSerializer(data=data)

#         self.assertFalse(serializer.is_valid(), serializer.errors)

#         #Vérifier que les valeurs sont bien échappées
        
#         print("Erreur de validation :", serializer.errors)
        
#         if serializer.is_valid() :
#             validated_data = serializer.validated_data
#             print("Username après nettoyage :" , validated_data["username"])
#             print("Lastname après nettoyage :", validated_data["lastname"])

class ShopSerializeurTest(TestCase) : 
    

    def test_valid_name(self):
        """Test avec des données valides"""
        data = {
            "name" : "Boutique1"
        }
        
        serializer = ShopSerializer(data=data)

        # Vérifier que le sérialiseur est valide
        self.assertTrue(serializer.is_valid(), serializer.errors)
    def test_(self) : 
        data = {
            "name" : "Boutique@34"
        }
        serializer = ShopSerializer(data=data)
        self.assertFalse(serializer.is_valid(), serializer.errors)

    def test_special_characters(self) : 
        data = {
            "name" : "Boutique@1"
        }
        serializer = ShopSerializer(data=data)
        self.assertFalse(serializer.is_valid(), serializer.errors)

    def test_input_empty(self) : 
        data = {
            "name" : ""
        }
        serializer = ShopSerializer(data=data)
        self.assertFalse(serializer.is_valid(), serializer.errors)


        

        
