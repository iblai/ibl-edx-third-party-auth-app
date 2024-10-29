import json
import logging

from common.djangoapps.third_party_auth.models import OAuth2ProviderConfig
from django.conf import settings
from django.contrib.auth import get_user_model
from social_core.backends.oauth import BaseOAuth2
from social_django.utils import load_strategy

logger = logging.getLogger(__name__)

User = get_user_model()


class IBLProviderConfig:
    """
    Get the provider config for the given provider.
    """

    def get_audience(self, backend):
        """
        Get the audience for the given provider.
        """
        try:
            provider = OAuth2ProviderConfig.objects.filter(slug=backend).latest(
                "change_date"
            )
            provider_config = json.loads(provider.other_settings)
            audience = provider_config.get("AUDIENCE")
            return audience
        except OAuth2ProviderConfig.DoesNotExist:
            logger.error("Provider not found")
            return {}

    def get_provider_slug_by_platform_key(username, platform_key):
        """
        Find the provider slug based on the username and platform_key.

        Args:
        username (str): The username of the user.
        platform_key (str): The platform key to match in the provider's other_settings.

        Returns:
        str: The slug of the matching provider, or None if no match is found.
        """
        logger.info(
            f"Searching for provider slug with username: {username} and platform_key: {platform_key}"
        )

        try:
            user = User.objects.get(username=username)
            logger.info(f"User found: {user}")
        except User.DoesNotExist:
            logger.warning(f"User not found with username: {username}")
            return None

        strategy = load_strategy()
        backends = strategy.get_backends().values()
        logger.info(f"Loaded {len(backends)} backends")

        for backend in backends:
            if isinstance(backend, BaseOAuth2):
                logger.debug(f"Checking backend: {backend.name}")
                other_settings = getattr(backend, "other_settings", {})
                backend_platform_key = other_settings.get("platform_key")
                logger.debug(
                    f"Backend {backend.name} platform_key: {backend_platform_key}"
                )
                if backend_platform_key == platform_key:
                    logger.info(f"Matching provider found: {backend.name}")
                    return backend.name

        logger.warning(f"No matching provider found for platform_key: {platform_key}")
        return None


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
