import logging

from common.djangoapps.third_party_auth.models import (
    _LTI_BACKENDS,
    _PSA_OAUTH2_BACKENDS,
    _PSA_SAML_BACKENDS,
    LTIProviderConfig,
    OAuth2ProviderConfig,
    SAMLConfiguration,
    SAMLProviderConfig,
)
from django.contrib.sites.models import Site
from openedx.core.djangoapps.theming.helpers import get_current_request

log = logging.getLogger(__name__)


def _enabled_providers(cls):
    """Modifications:
    - for _PSA_OAUTH2_BACKENDS, use site_id instead of just backend_name for
        key_values and current.
    - iterate over backend_name, site instead of just backend_name
    """
    oauth2_backend_names = OAuth2ProviderConfig.key_values("backend_name", "site_id")
    for oauth2_backend_name, site in oauth2_backend_names:
        provider = OAuth2ProviderConfig.current(oauth2_backend_name, site)
        if (
            provider.enabled_for_current_site
            and provider.backend_name in _PSA_OAUTH2_BACKENDS
        ):
            yield provider
    if SAMLConfiguration.is_enabled(
        Site.objects.get_current(get_current_request()), "default"
    ):
        idp_slugs = SAMLProviderConfig.key_values("slug", flat=True)
        for idp_slug in idp_slugs:
            provider = SAMLProviderConfig.current(idp_slug)
            if (
                provider.enabled_for_current_site
                and provider.backend_name in _PSA_SAML_BACKENDS
            ):
                yield provider
    for consumer_key in LTIProviderConfig.key_values("lti_consumer_key", flat=True):
        provider = LTIProviderConfig.current(consumer_key)
        if provider.enabled_for_current_site and provider.backend_name in _LTI_BACKENDS:
            yield provider


def get_enabled_by_backend_name(cls, backend_name):
    """Modifications:
    - for _PSA_OAUTH2_BACKENDS, use site_id instead of just backend_name for
        key_values and current.
    - iterate over backend_name, site instead of just backend_name
    """
    if backend_name in _PSA_OAUTH2_BACKENDS:
        oauth2_backend_names = OAuth2ProviderConfig.key_values(
            "backend_name", "site_id"
        )
        for oauth2_backend_name, site in oauth2_backend_names:
            provider = OAuth2ProviderConfig.current(oauth2_backend_name, site)
            if (
                provider.backend_name == backend_name
                and provider.enabled_for_current_site
            ):
                yield provider
    elif backend_name in _PSA_SAML_BACKENDS and SAMLConfiguration.is_enabled(
        Site.objects.get_current(get_current_request()), "default"
    ):
        idp_names = SAMLProviderConfig.key_values("slug", flat=True)
        for idp_name in idp_names:
            provider = SAMLProviderConfig.current(idp_name)
            if (
                provider.backend_name == backend_name
                and provider.enabled_for_current_site
            ):
                yield provider
    elif backend_name in _LTI_BACKENDS:
        for consumer_key in LTIProviderConfig.key_values("lti_consumer_key", flat=True):
            provider = LTIProviderConfig.current(consumer_key)
            if (
                provider.backend_name == backend_name
                and provider.enabled_for_current_site
            ):
                yield provider


def patch():
    from common.djangoapps.third_party_auth import provider

    provider.Registry._enabled_providers = classmethod(_enabled_providers)
    provider.Registry.get_enabled_by_backend_name = classmethod(
        get_enabled_by_backend_name
    )
