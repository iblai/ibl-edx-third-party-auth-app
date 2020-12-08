# IBL-Edx-Third-Party-Auth
This is a modification to the base edx `third_party_auth` application to support using variations of the same provider on each subdomain. This was built specifically with `KeyCloak` in mind to support a different realm on each subdomain.

Updates to this package also add support for dynamically modifying the `OAuth2ProviderConfigs` through OAuth2 Protected API endpoints.

This document covers installation and backend setup. For customer facing usage and setup see the `USAGE.md` file.

## Installation
This package is meant to replace the built in edx `third_party_auth` auth package.

- rename the `third_party_auth` directory in `edx-platform/common/djangoapps/` to `third_party_auth_old`
- `sudo -Hu edxapp /edx/bin/pip.edxapp install git+https://gitlab.com/iblstudios/ibl-edx-third-party-auth`

## EdX Setup
- Become the root `sudo -i`
- Open `edx-platform/lms/envs/common.py`
    - Add `'third_party_auth.backends.KeycloakOAuth2'` to `AUTHENTICATION_BACKENDS`
- In `lms.env.json`:
    - Under `FEATURES`, set `"ENABLE_THIRD_PARTY_AUTH": true`
    - Set all the fields under `REGISTRATION_EXTRA_FIELDS` to `hidden`
- Activate the venv: `source /edx/app/edxapp/venvs/edxapp/bin/activate`
- Navigate to `/edx/app/edxapp/edx-platform`
- Run: `./manage.py lms migrate third_party_auth --settings=production`
- Restart the lms: `/edx/bin/supervisorctl restart lms cms`

### Enabling Auto Login for SSO Keycloak
If you want to enable auto login for each domain to their keycloak realm:

- Follow installation instructions for installing the [ibl-tpa-middleware](https://gitlab.com/iblstudios/ibl-tpa-middleware) package
- Add it to the middleware as the second to last entry (leave `SessionCookieDomainOverrideMiddleware` at the end)
- Set `IBL_TPA_MIDDLEWARE_DEFAULT_PROVIDER = 'keycloak'` in `lms/envs/common.py`

### Adding SSO to the CMS (via an external IDP)
When adding SSO to the CMS (disabling SSO over LMS and using some IDP), complete the following:

In `cms/envs/common.py`:
* Add `'third_party_auth.backends.KeycloakOAuth2',` to the front of the `AUTHENTICATION_BACKENDS` list
* Add `'ibl_tpa.middleware.TPAMiddleware',` as the second to last entry in the `MIDDLEWARE_CLASSES` list
* Add `third_party_auth` to the `INSTALLED_APPS`
* Add the following to the bottom of the file:

```python
TPA_PROVIDER_BURST_THROTTLE = '10/min'
TPA_PROVIDER_SUSTAINED_THROTTLE = '50/hr'
IBL_TPA_MIDDLEWARE_TARGET_URLS = {'/login', '/register', '/signup', '/signin'}
IBL_TPA_MIDDLEWARE_DEFAULT_PROVIDER = 'keycloak'
TPA_LOGOUT_PROVIDER = 'keycloak'
TPA_ENABLE_OP_SESSION_MANAGEMENT = True
```

In `cms.env.json`, under `FEATURES`, add/edit the following:
* `"ENABLE_THIRD_PARTY_AUTH": true,`
* `"DISABLE_STUDIO_SSO_OVER_LMS": true,`


In `cms/urls.py`:
* Setup the beginning of the `urlpatterns` definition as follows:

```python
urlpatterns = []
# Third-party auth.
if settings.FEATURES.get('ENABLE_THIRD_PARTY_AUTH'):
    urlpatterns += [
        url(r'', include('third_party_auth.urls')),
        url(r'api/third_party_auth/', include('third_party_auth.api.urls')),
    ]

# Start of normal CMS urlpatterns
# IMPORTANT: The only change here is making `=` -> `+=`
urlpatterns += [
    url(r'', include('openedx.core.djangoapps.user_authn.urls_common')),
    ...
```

The third party patterns need to come first because they include an override of the `logout` endpoint.

**IMPORTANT**: Note that the `urlpatterns` after the "Start of normal CMS urlpattern" comment have to be appended now. (`urlpatterns = [...]` -> `urlpatterns += [...]`)

Restart the CMS.

### LMS Template Updates
**Note:** This requires the [LMS theming engine](https://gitlab.com/iblstudios/iblx-lms/) to be installed.

This adds support for the rp-check-session endpoint to the LMS
* Copy the file in `third_party_auth/templates/third_party_auth/iblx-check-session-rp.html` to `edx-platform/themes/iblx/lms/templates/client/body-final.html` (create directory if necessary)
   * *Note*: If the file has existing content, append appropriately
* Change the owner:group of that file to `edxapp:edxapp`

Command:
```
sudo -Hu edxapp mkdir -p  /edx/app/edxapp/edx-platform/themes/iblx/lms/templates/client

sudo -Hu edxapp cp /edx/app/edxapp/venvs/edxapp/lib/python2.7/site-packages/third_party_auth/templates/third_party_auth/iblx-check-session-rp.html /edx/app/edxapp/edx-platform/themes/iblx/lms/templates/client/body-final.html
```

### CMS Template Updates
**Note:** This requires the [CMS theming engine](https://gitlab.com/iblstudios/iblx-cms/) to be installed.

This adds support for the rp-check-session endpoint to the CMS
* Copy the file in `third_party_auth/templates/third_party_auth/iblx-check-session-rp.html` to `edx-platform/themes/iblx/cms/templates/client/body-initial.html` (create directory if necessary)
   * *Note*: If the file has existing content, append appropriately
* Change the owner:group of that file to `edxapp:edxapp`

Command:
```
sudo -Hu edxapp mkdir -p  /edx/app/edxapp/edx-platform/themes/iblx/cms/templates/client

sudo -Hu edxapp cp /edx/app/edxapp/venvs/edxapp/lib/python2.7/site-packages/third_party_auth/templates/third_party_auth/iblx-check-session-rp.html /edx/app/edxapp/edx-platform/themes/iblx/cms/templates/client/body-initial.html
```


#### Legacy
<details>
<summary>Manual Instructions</summary>

* Open `edx-platform/themes/iblx/cms/templates/base.html`
* Add the following after the `except ImportError` clause under the `# Hawthorn Imports` section:

```python
from django.conf import settings
from django.urls import reverse
ENABLE_OP_SESSION_MANAGEMENT = getattr(settings, "TPA_ENABLE_OP_SESSION_MANAGEMENT", False)
CHECK_SESSION_URL = "" if not ENABLE_OP_SESSION_MANAGEMENT else reverse('tpa-check-session-rp-iframe')
```

Add the following directly under the opening `body` tag:
```python
% if ENABLE_OP_SESSION_MANAGEMENT:
    <iframe style="display: none;" src="${CHECK_SESSION_URL}" frameborder="1" width="10" height="10"></iframe>
% endif
```
</details>


### LMS and CMS Site Configurations
There needs to be a `Site` and `Site Configuration` entry for both LMS and CMS. The `Site Configuration`s should have the `SESSION_COOKIE_DOMAIN` set to each of their respective domains.

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

- `TPA_LOGOUT_PROVIDER` = 'keycloak'
    - If not set, the default logout behavior is maintained
    - Default: `None`
    - If set to a backend name, it will retrieve that provider for the current site and then attempt to redirect to the value in that providers `other_settings['END_SESSION_URL']` endpoint after performing normal logout

If there is no `END_SESSION_URL` entry on the provider, default logout behavior will be performed.

The following are only relevant if `TPA_LOGOUT_PROVIDER` is set to a backend name. These settings will control a query string that can be appended to the end session URL and provide a redirect after logout out of the OP.

Query string format: `<TPA_POST_LOGOUT_REDIRECT_FIELD>=<TPA_POST_LOGOUT_REDIRECT_URL>`

- `TPA_POST_LOGOUT_REDIRECT_FIELD` = 'redirect_uri'`
    - Query string field name for post logout redirect from OP
    - Default: `redirect_uri`
- `TPA_POST_LOGOUT_REDIRECT_URL = 'https://your.domain.com'`
    - URL for post logout redirect from OP
    - Default: `current_site`
    - If set to `None`, then no redirect URI query string will be added to the end session endpoint

- `TPA_ENABLE_OP_SESSION_MANAGEMENT = True/False`
    - If enabled, adds the check session iframe to the LMS/CMS
    - This will log the user out of edx if their session status changes on the OP.
    - This will occur for users who have logged in after the setting is enabled.
