from django.apps import AppConfig
from django.conf import settings


class IBLThirdPartyAuthConfig(AppConfig):
    name = 'ibl_third_party_auth'
    verbose_name = "IBL Third-party Auth "

    def ready(self):
        from . import signals
        from .patches.patch import patch
        patch()
