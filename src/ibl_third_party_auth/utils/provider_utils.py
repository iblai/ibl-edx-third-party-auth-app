import json

from common.djangoapps.third_party_auth.models import OAuth2ProviderConfig


class IBLProviderConfig():
    """
    Get the provider config for the given provider.
    """
    def get_audience(self, backend):
        """
        Get the audience for the given provider.
        """
        provider = OAuth2ProviderConfig.objects.filter(slug=backend).latest('change_date')
        provider_config = json.loads(provider)
        audience = provider_config.get('AUDIENCE')
        return audience