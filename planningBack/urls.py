from django.urls import path, include
from django.contrib.auth import get_user_model
from rest_framework import routers, serializers, viewsets
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)
from back.views import add_admin, login, get_user_role, LogoutView, ShopView, ContratView, EmployerView# ✅ Import de la vue

# Serializers define the API representation.
User = get_user_model()
class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'is_staff']

# ViewSets define the view behavior.
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter()
router.register(r'users', UserViewSet)

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('api/add_admin/', add_admin, name='add_admin'),
    path('api/login/', login, name='login'),
    path('api/get_user_role/', get_user_role, name='get_user_role'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('api/shop/',ShopView.as_view(), name='add_shop'),
    path('api/shops/<int:shop_id>/', ShopView.as_view(), name='delete_shop'),
    path('api/contrat/', ContratView.as_view(), name="add_contrat"),
    path('api/add_employer/<int:contrat_id>/<int:shop_id>/', EmployerView.as_view(), name="add_employer")
]
