from tutor import hooks

hooks.Filters.ENV_PATCHES.add_item(
    (
        "common-env-features",
        "ENABLE_THIRD_PARTY_AUTH = True"
    )
)
hooks.Filters.ENV_PATCHES.add_item(
    (
        "cms-env-features",
        "DISABLE_STUDIO_SSO_OVER_LMS = True"
    )
)
hooks.Filters.ENV_PATCHES.add_item(
    (
        "openedx-lms-common-settings",
        """REGISTRATION_EXTRA_FIELDS =  {
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
        """
    )
)


hooks.Filters.ENV_PATCHES.add_item(
    (
        "openedx-cms-common-settings",
        "TPA_PROVIDER_BURST_THROTTLE = '10/min'"
    )
)
hooks.Filters.ENV_PATCHES.add_item(
    (
        "openedx-cms-common-settings",
        "TPA_PROVIDER_SUSTAINED_THROTTLE = '50/hr'"
    )
)
hooks.Filters.ENV_PATCHES.add_item(
    (
        "openedx-cms-common-settings",
        "IBL_TPA_MIDDLEWARE_TARGET_URLS = {'/login', '/register', '/signup', '/signin'}"
    )
)
hooks.Filters.ENV_PATCHES.add_item(
    (
        "openedx-cms-common-settings",
        "IBL_TPA_MIDDLEWARE_DEFAULT_PROVIDER = 'keycloak'"
    )
)
hooks.Filters.ENV_PATCHES.add_item(
    (
        "openedx-cms-common-settings",
        "IBL_CMS_PREVENT_CONCURRENT_LOGINS = True"
    )
)