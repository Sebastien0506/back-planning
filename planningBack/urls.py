from django.urls import path, include
from django.contrib.auth import get_user_model
from rest_framework import routers, serializers, viewsets
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)
from back.views import add_admin, login, get_user_role, LogoutView, ShopView, ContratView, EmployerListView, EmployerDetailAPIView, VacationAPIVew# ✅ Import de la vue

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
    path('api/shop_update/<int:shop_id>/', ShopView.as_view(), name='update_shop'),
    path('api/contrat/', ContratView.as_view(), name="add_contrat"),
    path('api/view_contrat/', ContratView.as_view(), name="view_contrat"),
    path('api/delete_contrat/<int:contrat_id>/', ContratView.as_view(), name="delete_contrat"),
    path('api/add_employer/<int:contrat_id>/<int:shop_id>/', EmployerListView.as_view(), name="add_employer"),
    path('api/view_employes/', EmployerListView.as_view(), name="view_emloyes"),
    path('api/delete_employe/<int:employer_id>/', EmployerListView.as_view(), name="delete_employe"),
    path('api/detail_employe/<int:pk>/', EmployerDetailAPIView.as_view(), name='detail_employe'),
    path('api/up_employer/<int:employer_id>/', EmployerDetailAPIView.as_view(), name="up_employe"),
    path('api/add_vacation/<int:employer_id>/', VacationAPIVew.as_view(), name="add_vacation"),
    path('api/view_vacation/', VacationAPIVew.as_view(), name="view_vacation"),
    path('api/vacation_status/<int:employer_id>/<int:vacation_id>/', VacationAPIVew.as_view(), name="vacation_status"),
    path("api/password_reset/", include("django_rest_passwordreset.urls", namespace="password_reset")),
]
