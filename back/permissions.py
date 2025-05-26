# myapp/permissions.py
import traceback
from rest_framework.permissions import BasePermission
from rest_framework_simplejwt.authentication import JWTAuthentication

class IsSuperAdminViaCookie(BasePermission):
    """
    Vérifie que l'utilisateur est authentifié via un JWT dans les cookies
    et qu'il a le rôle 'superadmin'.
    """

    def has_permission(self, request, view):
        token = request.COOKIES.get('access_token')

        if not token:
            return False

        jwt_auth = JWTAuthentication()
        try:
            validated_token = jwt_auth.get_validated_token(token)
            user = jwt_auth.get_user(validated_token)
            request.user = user  # Injection de l'utilisateur dans la requête

            # Vérifie le rôle
            return getattr(user, "role", None) == "superadmin"

        except Exception:
            traceback.print_exc()
            return False