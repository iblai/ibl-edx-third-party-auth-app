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

    def ready(self):
        """
        Import and apply patches when the app is ready.
        """
        log.info("IBLThirdPartyAuthConfig.ready() called")

        try:
            from common.djangoapps.third_party_auth import appleid

            log.info(f"Current AppleIdAuth class: {appleid.AppleIdAuth}")

            from .patches.patch_apple_id import patch as patch_apple_id
            from .patches.patch_middleware import patch as patch_middleware

            # Apply patches
            patch_apple_id()
            patch_middleware()

            log.info(f"After patching, AppleIdAuth class: {appleid.AppleIdAuth}")
        except Exception as e:
            log.error(f"Error during patching: {str(e)}", exc_info=True)
