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


def get_monitored_providers():
    """
    Get the list of provider names that should be monitored for social auth creation.

    Returns:
        list: List of provider names to monitor. Defaults to ['azuread-oauth2'] if not specified
    """
    default_providers = ["azuread-oauth2"]
    providers = getattr(settings, "MONITORED_PROVIDERS", default_providers)

    # Handle string input for backward compatibility
    if isinstance(providers, str):
        providers = [providers]

    return providers


def get_social_auth_users_by_provider(provider):
    """
    Get all UserSocialAuth entries for a specific provider.

    Args:
        provider (str): The provider name (e.g., 'azuread-oauth2')

    Returns:
        QuerySet: A queryset of UserSocialAuth objects
    """
    from social_django.models import UserSocialAuth

    return UserSocialAuth.objects.filter(provider=provider)
