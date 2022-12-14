import logging

log = logging.getLogger(__name__)


def patch():
    """
    - models - OAuth2ProviderConfig(ProviderConfig) - DONE
    - provider.py - DONE
    - settings.py - Maybe don't need to do now?
    - strategy.py - DONE
    - All tests
    """
    from . import patch_provider, patch_models, patch_strategy, patch_logoutview

    patch_strategy.patch()
    patch_provider.patch()
    patch_models.patch()
    patch_logoutview.patch()
