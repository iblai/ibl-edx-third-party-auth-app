import json
import logging

from common.djangoapps.third_party_auth.models import OAuth2ProviderConfig
from django.conf import settings

logger = logging.getLogger(__name__)


def get_provider_config_by_backend(backend_name):
    """
    Get the most recent enabled provider config for a given backend name.

    Args:
        backend_name (str): The name of the backend (e.g., 'azuread-oauth2')

    Returns:
        OAuth2ProviderConfig: The most recent enabled provider config, or None if not found
    """
    try:
        provider = OAuth2ProviderConfig.objects.filter(
            backend_name=backend_name, enabled=True
        ).latest("change_date")
        return provider
    except OAuth2ProviderConfig.DoesNotExist:
        logger.error(f"No enabled provider config found for backend: {backend_name}")
        return None


def get_platform_key_from_provider(provider_config):
    """
    Extract platform key from provider's other_settings.

    Args:
        provider_config (OAuth2ProviderConfig): The provider configuration object

    Returns:
        str: The platform key if found, None otherwise
    """
    try:
        other_settings = json.loads(provider_config.other_settings)
        platform_key = other_settings.get("platform_key")
        if not platform_key:
            logger.error("No platform_key found in provider configuration")
        return platform_key
    except json.JSONDecodeError:
        logger.error("Invalid JSON in provider other_settings")
        return None
    except Exception as e:
        logger.error(f"Error reading provider configuration: {str(e)}")
        return None


def get_monitored_provider():
    """
    Get the provider name that should be monitored for social auth creation.

    Returns:
        str: The provider name to monitor (defaults to 'azuread-oauth2')
    """
    return getattr(settings, "AZURE_PROVIDER", "azuread-oauth2")
