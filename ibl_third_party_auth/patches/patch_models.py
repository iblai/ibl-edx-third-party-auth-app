
import logging

from common.djangoapps.third_party_auth import models

log = logging.getLogger(__name__)


def provider_id(self):
    """ Unique string key identifying this provider. Must be URL and css class friendly. """
    assert self.prefix is not None
    return "-".join((self.prefix, ) + tuple(str(getattr(self, field)) for field in self.KEY_FIELDS))


def patch():
    models.OAuth2ProviderConfig.KEY_FIELDS = ('backend_name', 'site_id')
    models.OAuth2ProviderConfig.provider_id = property(provider_id)
