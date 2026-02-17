"""
App Configuration for ibl_third_party_auth
"""

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
    def _insert_pipeline_step():
        """Insert auto_create_user into SOCIAL_AUTH_PIPELINE before ensure_user_information."""
        from django.conf import settings

        pipeline = list(getattr(settings, "SOCIAL_AUTH_PIPELINE", []))
        target = "common.djangoapps.third_party_auth.pipeline.ensure_user_information"
        our_step = "ibl_third_party_auth.pipeline.auto_create_user"
        if target in pipeline and our_step not in pipeline:
            idx = pipeline.index(target)
            pipeline.insert(idx, our_step)
            settings.SOCIAL_AUTH_PIPELINE = tuple(pipeline)
            log.info("Inserted auto_create_user into SOCIAL_AUTH_PIPELINE at index %d", idx)
        elif our_step in pipeline:
            log.info("auto_create_user already in SOCIAL_AUTH_PIPELINE")
        else:
            log.warning(
                "Could not insert auto_create_user: ensure_user_information not found in pipeline"
            )

    def ready(self):
        """
        Import and apply patches when the app is ready.
        """
        log.info("IBLThirdPartyAuthConfig.ready() called")

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
            # Import all relevant modules
            from common.djangoapps.third_party_auth import appleid
            from social_core.backends import apple, azuread, google

            log.info(f"Current AppleIdAuth class: {appleid.AppleIdAuth}")
            log.info(f"Current social_core AppleIdAuth class: {apple.AppleIdAuth}")
            log.info(f"Current AzureADOAuth2 class: {azuread.AzureADOAuth2}")
            log.info(f"Current GoogleOAuth2 class: {google.GoogleOAuth2}")

            from .patches.patch_apple_id import patch as patch_apple_id
            from .patches.patch_azuread import patch as patch_azuread
            from .patches.patch_google import patch as patch_google
            from .patches.patch_middleware import patch as patch_middleware

            # Apply patches
            patch_apple_id()
            patch_azuread()
            patch_middleware()
            patch_google()

            # Verify patches
            log.info(f"After patching appleid.AppleIdAuth: {appleid.AppleIdAuth}")
            log.info(f"After patching apple.AppleIdAuth: {apple.AppleIdAuth}")
            log.info(f"After patching azuread.AzureADOAuth2: {azuread.AzureADOAuth2}")
            log.info(f"After patching google.GoogleOAuth2: {google.GoogleOAuth2}")

            # We don't need to force reload the backend during app initialization
            # The backend will be loaded correctly when needed during requests

        except Exception as e:
            log.error(f"Error during patching: {str(e)}", exc_info=True)

        # Insert our auto_create_user pipeline step before ensure_user_information.
        # This must happen in ready() because SOCIAL_AUTH_PIPELINE is set by
        # ThirdPartyAuthConfig.ready() → apply_settings(), which runs before
        # our ready() (third_party_auth is earlier in INSTALLED_APPS).
        # plugin_settings() runs too early — during settings module loading,
        # before any AppConfig.ready() has been called.
        self._insert_pipeline_step()

        # Import signal handlers
        import ibl_third_party_auth.signals  # noqa
