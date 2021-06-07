import logging

from django.apps import AppConfig
from django.conf import settings

log = logging.getLogger(__name__)


def _noop(*args, **kwargs):
    return


class IBLThirdPartyAuthConfig(AppConfig):
    name = 'ibl_third_party_auth'
    verbose_name = "IBL Third-party authentication"

    def ready(self):
        # To override the settings before loading social_django.
        from .patches.patch import patch
        patch()

    def _enable_third_party_auth(self):
        """
        Enable the use of third_party_auth, which allows users to sign in to edX
        using other identity providers. For configuration details, see
        common/djangoapps/third_party_auth/settings.py.
        """
        from common.djangoapps.third_party_auth import settings as auth_settings
        auth_settings.apply_settings(settings)

        from common.djangoapps.third_party_auth import signals

        from openedx.core.djangoapps.user_authn import cookies
        if getattr(settings, "IBL_DISABLE_MARKETING_COOKIES", True):
            cookies._set_deprecated_logged_in_cookie = _noop
            log.info("Patched _set_deprecated_logged_in_cookie with no-op")
            cookies._set_deprecated_user_info_cookie = _noop
            log.info("Patched _set_depercated_user_info_cookie with no-op")

