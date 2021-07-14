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
    settings.AUTHENTICATION_BACKENDS.insert(0, 'ibl_third_party_auth.backends.KeycloakOAuth2')
