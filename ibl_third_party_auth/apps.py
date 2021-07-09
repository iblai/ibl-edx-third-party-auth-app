"""
App Configuration for ibl_third_party_auth
"""
from django.apps import AppConfig
from django.conf import settings

class IBLThirdPartyAuthConfig(AppConfig):
    """
    App Configuration for ibl_third_party_auth
    """
    name = 'ibl_third_party_auth'
    verbose_name = "IBL Third-party Auth"

    plugin_app = {
        'url_config': {
            'lms.djangoapp': {
                'namespace': 'ibl_third_party_auth',
                'regex': r'',
                'relative_path': 'ibl_third_party_auth.urls',
            },
        },
        'settings_config': {
            'lms.djangoapp': {
                'common': {
                    'relative_path': 'settings.common',
                },
            },
        }
    }

    def ready(self):
        from . import signals
        from .patches.patch import patch
        patch()