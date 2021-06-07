import logging

log = logging.getLogger(__name__)


def patch():
    """
    - models - OAuth2ProviderConfig(ProviderConfig)
    - provider.py
    - settings.py
    - strategy.py
    - All tests
    """
    from . import patch_provider, patch_models
    patch_provider.patch()
    patch_models.patch()
