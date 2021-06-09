from rest_framework.routers import DefaultRouter

from .views import OAuthProvidersViewset

router = DefaultRouter()
router.register(r'v0/oauth-providers/(?P<backend>[\w.+-]+)', OAuthProvidersViewset,
                basename='third_party_auth_oauth_providers')


urlpatterns = router.urls
