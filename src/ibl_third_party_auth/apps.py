"""
App Configuration for ibl_third_party_auth
"""

import functools
import logging

from django.apps import AppConfig

log = logging.getLogger(__name__)


class IBLThirdPartyAuthConfig(AppConfig):
    """
    App Configuration for ibl_third_party_auth
    """

    name = "ibl_third_party_auth"
    verbose_name = "IBL Third-party Auth"

    plugin_app = {
        "url_config": {
            "lms.djangoapp": {
                "namespace": "ibl_third_party_auth",
                "regex": r"",
                "relative_path": "urls",
            },
            "cms.djangoapp": {
                "namespace": "ibl_third_party_auth",
                "regex": r"",
                "relative_path": "urls",
            },
        },
        "settings_config": {
            "lms.djangoapp": {
                "common": {
                    "relative_path": "settings.common",
                },
            },
            "cms.djangoapp": {
                "common": {
                    "relative_path": "settings.common",
                },
            },
        },
    }

    @staticmethod
    def _patch_ensure_user_information():
        """
        Monkey-patch ensure_user_information to auto-create SSO users.

        This is more reliable than inserting into SOCIAL_AUTH_PIPELINE because
        the pipeline tuple can be set/overwritten at various points during
        startup.  Patching the function on the module is the same proven
        approach used for the Apple ID, Azure AD, and Google patches.
        """
        try:
            from common.djangoapps.third_party_auth import pipeline as tpa_pipeline
            from ibl_third_party_auth.pipeline import auto_create_user

            original_ensure = tpa_pipeline.ensure_user_information

            @functools.wraps(original_ensure)
            def patched_ensure(*args, **kwargs):
                if kwargs.get("user") is None:
                    result = auto_create_user(**kwargs)
                    if result and isinstance(result, dict) and "user" in result:
                        kwargs.update(result)
                        # Call original — it sees an active user and returns None
                        original_ensure(*args, **kwargs)
                        # Return our dict so the pipeline accumulates user/is_new
                        return result
                return original_ensure(*args, **kwargs)

            tpa_pipeline.ensure_user_information = patched_ensure
            log.info("Patched ensure_user_information to auto-create SSO users")
        except Exception:
            log.exception("Failed to patch ensure_user_information")

    def ready(self):
        """
        Import and apply patches when the app is ready.
        """
        # Fix oauth2_provider settings initialization order issue
        # In multi-node Open edX deployments, oauth2_settings.SCOPES can get cached
        # in __dict__ before Django's OAUTH2_PROVIDER setting is fully loaded.
        # This causes Studio SSO login to fail with invalid_scope errors because
        # only default scopes {'read', 'write'} are available instead of the full
        # set including 'user_id', 'profile', 'email'.
        # We clear all cached attributes so they get re-read from Django settings.
        try:
            from oauth2_provider.settings import oauth2_settings

            # Clear ALL cached attributes including SCOPES that may have been
            # cached before Django settings were fully loaded
            for attr in list(oauth2_settings.__dict__.keys()):
                if attr.isupper() and attr not in ('DEFAULTS',):
                    try:
                        delattr(oauth2_settings, attr)
                    except AttributeError:
                        pass
            oauth2_settings._cached_attrs.clear()
            if hasattr(oauth2_settings, '_user_settings'):
                delattr(oauth2_settings, '_user_settings')
            log.info("Cleared oauth2_provider cached settings to fix scope initialization")
        except ImportError:
            log.debug("oauth2_provider not installed, skipping settings fix")
        except Exception as e:
            log.warning(f"Error clearing oauth2_provider settings cache: {e}")

        try:
            from .patches.patch_apple_id import patch as patch_apple_id
            from .patches.patch_azuread import patch as patch_azuread
            from .patches.patch_google import patch as patch_google
            from .patches.patch_middleware import patch as patch_middleware

            patch_apple_id()
            patch_azuread()
            patch_middleware()
            patch_google()
        except Exception:
            log.exception("Error during patching")

        # Monkey-patch ensure_user_information so new SSO users are auto-created
        # before the function checks for a user and redirects to registration.
        self._patch_ensure_user_information()

        # Import signal handlers
        import ibl_third_party_auth.signals  # noqa
