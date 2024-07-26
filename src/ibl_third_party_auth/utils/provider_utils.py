import json
import logging

from common.djangoapps.third_party_auth.models import OAuth2ProviderConfig

log = logging.getLogger(__name__)

class IBLProviderConfig():
    """
    Get the provider config for the given provider.
    """
    def get_audience(self, backend):
        """
        Get the audience for the given provider.
        """
        try:
            provider = OAuth2ProviderConfig.objects.filter(slug=backend).latest('change_date')
            provider_config = json.loads(provider.other_settings)
            audience = provider_config.get('AUDIENCE')
            return audience
        except OAuth2ProviderConfig.DoesNotExist:
            log.error("Provider not found")
            return {}