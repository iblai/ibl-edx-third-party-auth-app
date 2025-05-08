"""
Third Party Auth REST API views
"""

from common.djangoapps.third_party_auth.models import OAuth2ProviderConfig
from openedx.core.lib.api.authentication import BearerAuthentication
from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAdminUser, IsAuthenticated

from . import serializers


class CreateReadListViewset(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    """Base class for providing Create, List, and Retrieve object methods"""

    pass


class OAuthProvidersViewset(CreateReadListViewset):
    """API viewset to dynamically Create/List/Retrieve OAuth2 Clients"""

    serializer_class = serializers.OAuthProviderSerializer
    authentication_classes = [BearerAuthentication]
    permission_classes = [IsAuthenticated, IsAdminUser]
    pagination_class = None

    def get_queryset(self):
        """Return most recent config for each slug/site combo for backend"""
        queryset = OAuth2ProviderConfig.objects.current_set().order_by("site__domain")
        queryset = queryset.filter(backend_name=self.kwargs.get("backend"))
        return queryset

    def get_serializer_context(self):
        """Add list of required field for other_settings

        These are mostly only required for keycloak, which is what we are
        implementing this for. This could be extended or changed for other
        backends
        """
        context = super(OAuthProvidersViewset, self).get_serializer_context()
        context["required_other_settings"] = [
            "AUTHORIZATION_URL",
            "ACCESS_TOKEN_URL",
            "PUBLIC_KEY",
            "logout_url",
            "ISS",
        ]
        return context
