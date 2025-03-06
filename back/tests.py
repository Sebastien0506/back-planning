from django.test import TestCase
from django.contrib.auth.hashers import identify_hasher
from back.serializer import AdministrateurSerializer, loginSerializeur

# class AdministrateurSerializerTest(TestCase):
#     """Tests pour le sérialiseur AdministrateurSerializer"""

#     def test_valid_data(self):
#         """Test avec des données valides"""
#         data = {
#             "username": "adminTest",
#             "lastname": "Dupont",
#             "email": "admin@example.com",
#             "password": "SecurePass123"
#         }
        
#         serializer = AdministrateurSerializer(data=data)

#         # Vérifier que le sérialiseur est valide
#         self.assertTrue(serializer.is_valid(), serializer.errors)

#         # ✅ Exécuter create() et vérifier le mot de passe haché
#         saved_admin = serializer.save()

#         # ✅ Vérifier que le mot de passe a bien été haché
#         hasher = identify_hasher(saved_admin.password)  # Récupère l'algorithme de hachage utilisé
#         print("Mot de passe après validation :", saved_admin.password)

#         # ✅ Vérifier que le hash utilise un algorithme sécurisé
#         self.assertIn(hasher.algorithm, ["bcrypt_sha256"])

#     def test_invalid_email(self):
#         """Test avec un email invalide"""
#         data = {
#             "username": "adminTest",
#             "lastname": "Dupont",
#             "email": "invalid-email",
#             "password": "SecurePass123"
#         }
#         serializer = AdministrateurSerializer(data=data)
        
#         # Vérifier que le sérialiseur est invalide
#         self.assertFalse(serializer.is_valid())

#         # Vérifier que l'erreur concerne bien l'email
#         self.assertIn("email", serializer.errors)

#     def test_xss_protection(self):
          
#          """Test que les scripts XSS sont bien échappés"""
        
#          data = {
            
#             "username": "Jean-@<script>alert('hello world')</script>Luc",
            
#             "lastname": "Dupont",
            
#             "email": "user@example.com",
            
#             "password": "password123"
        
#          }

        
#          serializer = AdministrateurSerializer(data=data)

#     # Vérifier que le sérialiseur est valide après nettoyage
        
#          self.assertTrue(serializer.is_valid(), serializer.errors)

#     # Vérifier que les valeurs sont bien échappées
        
#          validated_data = serializer.validated_data
        
#          print("Username après nettoyage :", validated_data["username"])  # DEBUG
        
#          print("Lastname après nettoyage :", validated_data["lastname"])  # DEBUG

class LoginSerializeurTest(TestCase) : 
    """Test pour le sérializeur de Login"""

    def test_valide_email(self) : 
        data = {
            "email" : "adminTest@gmail.com",
            "password" : "Password1@",
        }   

        serializer = loginSerializeur(data=data)

        self.assertTrue(serializer.is_valid(), serializer.errors)
    
    def test_invalide_email(self) : 
        data = {
            "email" : "adminTest@@gmail.com",
            "password" : "Password1@",
        }

        serializer = loginSerializeur(data=data)

        self.assertFalse(serializer.is_valid(), serializer.errors)
    
    def test_password_valid(self) :
        data= {
            "email" : "admintest@gmail.com",
            "password" : "Password@1",

        }

        serializer = loginSerializeur(data=data)
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_invalid_password(self) : 
        data ={
            "email" : "adminTest@gmail.com",
            "password" : "password@1",
        }

        serializer = loginSerializeur(data=data)
        self.assertFalse(serializer.is_valid(), serializer.errors)

        

        
