from tutor import hooks

hooks.Filters.ENV_PATCHES.add_item((
"common-env-features",
"""
"ENABLE_THIRD_PARTY_AUTH": true

"""

))

hooks.Filters.ENV_PATCHES.add_item((
"cms-env-features",
"""
"DISABLE_STUDIO_SSO_OVER_LMS": true

"""

))

hooks.Filters.ENV_PATCHES.add_item((
"lms-env",
"""
"REGISTRATION_EXTRA_FIELDS": {
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

))

hooks.Filters.ENV_PATCHES.add_item((
"openedx-cms-common-settings",
"""
# ibl-edx-third-party-auth
TPA_PROVIDER_BURST_THROTTLE = '10/min'
TPA_PROVIDER_SUSTAINED_THROTTLE = '50/hr'
IBL_TPA_MIDDLEWARE_TARGET_URLS = {'/login', '/register', '/signup', '/signin'}
IBL_TPA_MIDDLEWARE_DEFAULT_PROVIDER = 'keycloak'
IBL_CMS_PREVENT_CONCURRENT_LOGINS = True

"""

))

