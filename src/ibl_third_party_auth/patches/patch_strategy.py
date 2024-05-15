import logging

from common.djangoapps.third_party_auth import strategy
from common.djangoapps.third_party_auth.models import OAuth2ProviderConfig
from common.djangoapps.third_party_auth.pipeline import AUTH_ENTRY_CUSTOM
from common.djangoapps.third_party_auth.pipeline import get as get_pipeline_from_request
from common.djangoapps.third_party_auth.provider import Registry
from social_core.backends.oauth import OAuthAuth
from social_django.strategy import DjangoStrategy

log = logging.getLogger(__name__)


class IBLConfigurationModelStrategy(DjangoStrategy):
    """
    NOTE: Copy of third_party_auth ConfigurationModelStrategy with slight
    modification to the call to `Oauth2ProviderConfig.current`
    -----

    A DjangoStrategy customized to load settings from ConfigurationModels
    for upstream python-social-auth backends that we cannot otherwise modify.
    """

    def setting(self, name, default=None, backend=None):
        """
        Load the setting from a ConfigurationModel if possible, or fall back to the normal
        Django settings lookup.

        OAuthAuth subclasses will call this method for every setting they want to look up.
        SAMLAuthBackend subclasses will call this method only after first checking if the
            setting 'name' is configured via SAMLProviderConfig.
        LTIAuthBackend subclasses will call this method only after first checking if the
            setting 'name' is configured via LTIProviderConfig.
        """
        if isinstance(backend, OAuthAuth):
            # NOTE: IBL PATCH -> Adds self.request.site.id to call to current
            provider_config = OAuth2ProviderConfig.current(
                backend.name, self.request.site.id
            )
            # IBL PATCH ENDS
            if not provider_config.enabled_for_current_site:
                raise Exception("Can't fetch setting of a disabled backend/provider.")
            try:
                return provider_config.get_setting(name)
            except KeyError:
                pass

        # special case handling of login error URL if we're using a custom auth entry point:
        if name == "LOGIN_ERROR_URL":
            auth_entry = self.request.session.get("auth_entry")
            if auth_entry and auth_entry in AUTH_ENTRY_CUSTOM:
                error_url = AUTH_ENTRY_CUSTOM[auth_entry].get("error_url")
                if error_url:
                    return error_url

        # Special case: we want to get this particular setting directly from the provider database
        # entry if possible; if we don't have the information, fall back to the default behavior.
        if name == "MAX_SESSION_LENGTH":
            running_pipeline = (
                get_pipeline_from_request(self.request) if self.request else None
            )
            if running_pipeline is not None:
                provider_config = Registry.get_from_pipeline(running_pipeline)
                if provider_config:
                    return provider_config.max_session_length

        # At this point, we know 'name' is not set in a [OAuth2|LTI|SAML]ProviderConfig row.
        # It's probably a global Django setting like 'FIELDS_STORED_IN_SESSION':
        # IBL PATCH STARTS
        return super(IBLConfigurationModelStrategy, self).setting(
            name, default, backend
        )
        # IBL PATCH ENDS


def patch():
    strategy.ConfigurationModelStrategy = IBLConfigurationModelStrategy
