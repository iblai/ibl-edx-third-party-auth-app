"""
Settings for the ibl_third_party_auth app.
"""

from os.path import abspath, dirname, join


def root(*args):
    """
    Get the absolute path of the given path relative to the project root.
    """
    return join(abspath(dirname(__file__)), *args)


USE_TZ = True

INSTALLED_APPS = (
    'ibl_third_party_auth',
)

def plugin_settings(settings):  # pylint: disable=unused-argument
    """
    Defines ibl_third_party_auth-specific settings when app is used as a plugin to edx-platform.
    """
    backends = getattr(settings, 'AUTHENTICATION_BACKENDS', None)
    if backends:
        settings.AUTHENTICATION_BACKENDS.insert(0, 'ibl_third_party_auth.backends.KeycloakOAuth2')
    else:
        settings.AUTHENTICATION_BACKENDS = ['ibl_third_party_auth.backends.KeycloakOAuth2']

    # Have to add to CMS's INSTALLED_APPS
    tpa = 'common.djangoapps.third_party_auth'
    if settings.ROOT_URLCONF.startswith('cms') and tpa not in settings.INSTALLED_APPS:
        settings.INSTALLED_APPS.append(tpa)
