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

    from . import patch_apple_id, patch_middleware
    patch_apple_id.patch()
    patch_middleware.patch()
