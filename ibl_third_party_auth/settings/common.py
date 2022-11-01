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


    # from the plugin
    settings.TPA_PROVIDER_BURST_THROTTLE = '10/min'
    settings.TPA_PROVIDER_SUSTAINED_THROTTLE = '50/hr'
    settings.IBL_TPA_MIDDLEWARE_TARGET_URLS = {'/login', '/register', '/signup', '/signin'}
    settings.IBL_TPA_MIDDLEWARE_DEFAULT_PROVIDER = 'keycloak'
    settings.IBL_CMS_PREVENT_CONCURRENT_LOGINS = True
    settings.REGISTRATION_EXTRA_FIELDS = {
        "city": "hidden",
        "confirm_email": "hidden",
        "country": "hidden",
        "gender": "hidden",
        "goals": "hidden",
        "honor_code": "hidden",
        "level_of_education": "hidden",
        "mailing_address": "hidden",
        "terms_of_service": "hidden",
        "year_of_birth": "hidden"
    }
    settings.FEATURES["DISABLE_STUDIO_SSO_OVER_LMS"] = True
    settings.FEATURES["ENABLE_THIRD_PARTY_AUTH"] = True

