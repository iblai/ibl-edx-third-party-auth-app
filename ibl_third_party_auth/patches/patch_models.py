
import logging

from common.djangoapps.third_party_auth import models

log = logging.getLogger(__name__)


def patch():
    models.OAuth2ProviderConfig.KEY_FIELDS = ('backend_name', 'site_id')
    log.info("Patched models.py")
