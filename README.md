# IBL-Edx-Third-Party-Auth
This appplication adds onto and patches the base edx `common.djangoapps.third_party_auth` app to support using variations of the same provider on each subdomain. This was built specifically with `KeyCloak` in mind to support a different realm on each subdomain.

Updates to this package also add support for dynamically modifying the `OAuth2ProviderConfigs` through OAuth2 Protected API endpoints.

This document covers installation and backend setup. For customer facing usage and setup see the `USAGE.md` file.

## Prereqs
- [ibl-tpa-middleware](https://gitlab.com/iblstudios/ibl-tpa-middleware)
    * Add to `INSTALLED_APPS` and add proper version to `MIDDLEWARE` (based on edx/django version)
- [iblx-cms theming](https://gitlab.com/iblstudios/iblx-cms)

## Installation
**Fresh Install**
```shell
sudo -Hu edxapp /bin/bash
source /edx/app/edxapp/edxapp_env
/edx/bin/pip.edxapp install git+https://gitlab.com/iblstudios/ibl-edx-third-party-auth@koa
```
**Upgrade**
```shell
sudo -Hu edxapp /bin/bash
source /edx/app/edxapp/edxapp_env
/edx/bin/pip.edxapp install --upgrade --no-deps --force-reinstall git+https://gitlab.com/iblstudios/ibl-edx-third-party-auth@koa
```

## EdX Setup
- Become the root `sudo -i`
- Open `lms/envs/common.py`
    - Add `ibl_third_party_auth` to `INSTALLED_APPS`
    - Add `'ibl_third_party_auth.backends.KeycloakOAuth2'` to `AUTHENTICATION_BACKENDS`
- In `/edx/etc/lms.yml`:
    - Under `FEATURES`, set `"ENABLE_THIRD_PARTY_AUTH": true`
    - Set all the fields under `REGISTRATION_EXTRA_FIELDS` to `hidden`
- In `lms/urls.py`:
    - Add `ibl_third_party_auth` urls in front of the original third part auth urls:

```python
# Third-party auth.
if settings.FEATURES.get('ENABLE_THIRD_PARTY_AUTH'):
    urlpatterns += [
        # IBL
        url(r'', include('ibl_third_party_auth.urls')),
        url(r'^api/third_party_auth/', include('ibl_third_party_auth.api.urls')),
        # Original
        url(r'', include('common.djangoapps.third_party_auth.urls')),
        url(r'^api/third_party_auth/', include('common.djangoapps.third_party_auth.api.urls')),
    ]
```

### Enabling Auto Login for SSO Keycloak
If you want to enable auto login for each domain to their keycloak realm:
- Ensure you've followed instructions for installing `ibl-tpa-middleware`
- Set `IBL_TPA_MIDDLEWARE_DEFAULT_PROVIDER = 'keycloak'` in `lms/envs/common.py`

Restart the LMS.

### Adding SSO to the CMS (via an external IDP)
When adding SSO to the CMS (disabling SSO over LMS and using some IDP), complete the following:

In `/edx/etc/studio.yml`, under `FEATURES`, add/edit the following under `FEATURES`:
* `ENABLE_THIRD_PARTY_AUTH: true`
* `DISABLE_STUDIO_SSO_OVER_LMS: true`

In `cms/envs/common.py`:
- Setup `ibl-tpa-middleware` like in the LMS (`INSTALLED_APPS`, `MIDDLEWARE`)
- Add `'ibl_third_party_auth.backends.KeycloakOAuth2',` to the front of the `AUTHENTICATION_BACKENDS` list
- Add `ibl_third_party_auth` to the `INSTALLED_APPS`
- Add the following to the bottom of the file:

```python
TPA_PROVIDER_BURST_THROTTLE = '10/min'
TPA_PROVIDER_SUSTAINED_THROTTLE = '50/hr'
IBL_TPA_MIDDLEWARE_TARGET_URLS = {'/login', '/register', '/signup', '/signin'}
IBL_TPA_MIDDLEWARE_DEFAULT_PROVIDER = 'keycloak'
IBL_CMS_PREVENT_CONCURRENT_LOGINS = True
```

In `cms/urls.py`:
* Setup the beginning of the `urlpatterns` definition as follows:

```python
urlpatterns = []
# Third-party auth
if settings.FEATURES.get('ENABLE_THIRD_PARTY_AUTH'):
    urlpatterns += [
        # IBL
        url(r'', include('ibl_third_party_auth.urls')),
        url(r'^api/third_party_auth/', include('ibl_third_party_auth.api.urls')),
        # Original
        url(r'', include('common.djangoapps.third_party_auth.urls')),
        url(r'^api/third_party_auth/', include('common.djangoapps.third_party_auth.api.urls')),
    ]

# Start of normal CMS urlpatterns
# IMPORTANT: The only change here is making `=` -> `+=`
urlpatterns += [
    url(r'', include('openedx.core.djangoapps.user_authn.urls_common')),
    ...
```

**IMPORTANT**: Note that the `urlpatterns` after the "Start of normal CMS urlpattern" comment have to be appended now. (`urlpatterns = [...]` -> `urlpatterns += [...]`)

Restart the CMS.

### LMS and CMS Site Configurations
There needs to be a `Site` and `Site Configuration` entry for both LMS and CMS. The `Site Configuration`s should have the `SESSION_COOKIE_DOMAIN` set to their respective domains.

*NOTE*: In newer environments, the following may be automatically configured.

In order for Studio to function properly, the following attributes needs to exist in the _CMS_ `Site Configuration`:

```json
{
  "site_domain":"studio.your.domain",
  "SITE_NAME":"studio.your.domain",
  "SESSION_COOKIE_DOMAIN":"studio.your.domain",
  "LMS_BASE":"org1.your.domain",
  "PREVIEW_LMS_BASE":"preview.your.domain",
  "course_org_filter":[
    "org1"
  ],
  "is_cms": true
}
```

The _LMS_ Site Configuration should _not_ specify the `is_cms` key and should set its `SESSION_COOKIE_DOMAIN` to its domain.

It's possible the CMS `Site Configuration` will be created through other means, but for completeness:

- The `PREVIEW/LMS_BASE` values should be the parent domain of the Studio domain
- The `course_org_filter` should list the org that will exist on that `LMS_BASE` domain
    - This is how `View Live` and `Preview` get the domain to use
    - Each org should only exist in _one_ CMS `Site Configuration`

### Optional Settings
The following settings are added in order to support redirecting to a default backend provider's end session endpoint.

See [here](https://openid.net/specs/openid-connect-session-1_0.html#RedirectionAfterLogout) for more information (section 5 and 5.1).

The following are only relevant if the backend provider has a `logout_url` set in it's `other_settings`. These settings will control a query string that can be appended to the end session URL and provide a redirect after logout out of the IDP.

Query string format: `<TPA_POST_LOGOUT_REDIRECT_FIELD>=<TPA_POST_LOGOUT_REDIRECT_URL>`

- `TPA_POST_LOGOUT_REDIRECT_FIELD` = 'redirect_uri'`
    - Query string field name for post logout redirect from OP
    - Default: `redirect_uri`
- `TPA_POST_LOGOUT_REDIRECT_URL = 'https://your.domain.com'`
    - URL for post logout redirect from OP
    - Default: `current_site`
    - If set to `None`, then no redirect URI query string will be added to the end session endpoint
