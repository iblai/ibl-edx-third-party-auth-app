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

INSTALLED_APPS = ("ibl_third_party_auth",)


def plugin_settings(settings):  # pylint: disable=unused-argument
    """
    Defines ibl_third_party_auth-specific settings when app is used as a plugin to edx-platform.
    """
    backends = getattr(settings, "AUTHENTICATION_BACKENDS", None)
    if backends:
        settings.AUTHENTICATION_BACKENDS.insert(
            0, "social_core.backends.google_openidconnect.GoogleOpenIdConnect"
        )
    else:
        settings.AUTHENTICATION_BACKENDS = [
            "social_core.backends.google_openidconnect.GoogleOpenIdConnect"
        ]

    # Insert our auto_create_user step before ensure_user_information so that
    # new SSO users get a User object created before that step checks for one.
    pipeline = list(getattr(settings, "SOCIAL_AUTH_PIPELINE", []))
    target = "common.djangoapps.third_party_auth.pipeline.ensure_user_information"
    our_step = "ibl_third_party_auth.pipeline.auto_create_user"
    if target in pipeline and our_step not in pipeline:
        idx = pipeline.index(target)
        pipeline.insert(idx, our_step)
        settings.SOCIAL_AUTH_PIPELINE = tuple(pipeline)

    # Have to add to CMS's INSTALLED_APPS
    tpa = "common.djangoapps.third_party_auth"
    if settings.ROOT_URLCONF.startswith("cms") and tpa not in settings.INSTALLED_APPS:
        settings.INSTALLED_APPS.append(tpa)
