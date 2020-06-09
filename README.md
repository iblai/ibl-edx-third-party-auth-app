# Cisco-Third-Party-Auth
This is a modification to the base edx `third_party_auth` application to support using variations of the same provider on each subdomain. This was built specifically with `KeyCloak` in mind to support a different realm on each subdomain.

Updates to this package also add support for dynamically modifying the `OAuth2ProviderConfigs` through OAuth2 Protected API endpoints.

This document covers installation and backend setup. For customer facing usage and setup see the `CUSTOMER_USAGE.md` file.

## Changes
The following are the major changes made to the edx base application:
- In `models.OAuth2ProviderConfig` we set `KEYS = ('slug', 'site_id')`
    - This means the current configuration is keyed off the `slug` and `site`, so we can use the same backend for different sites
        - Examples: `('keycloak', 'org1.domain.com'), ('keycloak', 'org2.domain.com')`
- In `provider.py` we modify the `Registry` class (where necessary) to fetch items based on the `slug`/`backend.name` and the `site.id`
- In `strategy.py` we fetch items based on the `slug`/`backend.name` and `site.id`
- Optionally changes the logout behavior to logout of a 'default' backend by redirecting to its `end session url` endpoint
- In `settings.py`:
    - Add `check_session_management` to pipeline

The requirement still holds that the `slug` must match the `backend_name` of the `OAuth2ProviderConfig`. This is automatically done when configuring with the external API.

The original edx implementation exists on the `base-edx-implementation` branch, so a diff can always be done there to see what has changed.

Each LMS and CMS Site domain requires a django `Site` model object and associated `Site Configuration` object.

## Test Updates
I made minor updates to the tests:
- updated expected `provider_id` values where necessary since that's composed of `KEYS` which used to be `slug` only and is now `slug`, `site_id`
- Instead of the Base test creating a new site, I have it fetch `Site.objects.all()[0]`
    - When `KEYS` was just `('slug',)`, it didn't matter which site was used. It's applied to the whole platform
    - In our case, the provider site needs to match the requests site

With these changes, all tests pass as they did before.

Added one additional test in `test_provider.py` that tests multiple keycloak providers being enabled.

## Installation
This package is meant to replace the built in `edx_third_party` auth package.

- rename the `third_party_auth` directory in `edx-platform/lms/common/djangoapps/` to `third_party_auth_old`
- `sudo -Hu edxapp /edx/bin/pip.edxapp install git+https://gitlab.com/iblstudios/cisco-third-party-auth`

## EdX Setup
- Become the root `sudo -i`
- Open `edx-platform/lms/envs/common.py`
    - Under `FEATURES`, Set `"ENABLE_THIRD_PARTY_AUTH": True`
    - Add `'third_party_auth.backends.KeycloakOAuth2'` to `AUTHENTICATION_BACKENDS`
- in `lms.env.json`, set all the fields under `REGISTRATION_EXTRA_FIELDS` to `hidden`
- Activate the venv: `source /edx/app/edxapp/venvs/edxapp/bin/activate`
- Navigate to `/edx/app/edxapp/edx-platform`
- Run: `./manage.py lms migrate third_party_auth --settings=production`
- Restart the lms: `/edx/bin/supervisorctl restart lms cms`

### Enabling Auto Login for SSO Keycloak
If you want to enable auto login for each domain to their keycloak realm:

- Follow installation instructions for installing the [ibl-tpa-middleware](https://gitlab.com/iblstudios/ibl-tpa-middleware) package
- Add it to the middleware as the second to last entry (leave `SessionCookieDomainOverrideMiddleware` at the end)
- Set `TPA_MIDDLEWARE_DEFAULT_PROVIDER = 'keycloak'` in `lms/envs/common.py`

### Adding SSO to the CMS (via an external IDP)
When adding SSO to the CMS (disabling SSO over LMS and using some IDP), complete the following:

In `cms/envs/common.py`:
* Add `'third_party_auth.backends.KeycloakOAuth2',` to the front of the `AUTHENTICATION_BACKENDS` list
* Add `'ibl_tpa.middleware.TPAMiddleware',` as the second to last entry in the `MIDDLEWARE_CLASSES` list
* Add `third_party_auth` to the `INSTALLED_APPS`
* Under `FEATURES`, Add `"ENABLE_THIRD_PARTY_AUTH": True,`
* Add the following to the bottom of the file:

```python
TPA_PROVIDER_BURST_THROTTLE = '10/min'
TPA_PROVIDER_SUSTAINED_THROTTLE = '50/hr'
TPA_MIDDLEWARE_TARGET_URLS = {'/login', '/register', '/signup', '/signin'}
TPA_MIDDLEWARE_DEFAULT_PROVIDER = 'keycloak'
TPA_LOGOUT_PROVIDER = 'keycloak'
TPA_ENABLE_OP_SESSION_MANAGEMENT = True
```

In `cms.envs.json`, under `FEATURES`, add/edit the following:
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

# Start of normal CMS urlpattersn
urlpatterns += [
    url(r'', include('openedx.core.djangoapps.user_authn.urls_common')),
    ...
```

The third party patterns need to come first because they include an override of the `logout` endpoint.

Restart the CMS.

### LMS Template Updates
**Note:** This requires the [lms theming engine](https://gitlab.com/iblstudios/iblx-lms/) to be installed.

This adds support for the rp-check-session endpoint to the lms
* Copy the file `third_party_auth/templates/third_party_auth/body-final.html` to: `edx-platform/themes/iblx/lms/templates/client/`
* Change the owner:group of that file to `edxapp:edxapp`

### CMS Template Updates
**Note:** This requires the [cms theming engine](https://gitlab.com/iblstudios/iblx-cms/) to be installed.

This adds support for the rp-check-session endpoint to the cms
* open `edx-platform/themes/iblx/cms/templates/base.html`
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

At some point, if a `body-extra.html` file can be included, we can move this into it.

### LMS and CMS Site Configurations
There needs to be a `Site` and `Site Configuration` entry for both LMS and CMS. The `Site Configuration`s should have the `SESSION_COOKIE_DOMAIN` set to each of their respective domains.

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

The _LMS_ Site Configration should _not_ specify the `is_cms` key and should set its `SESSION_COOKIE_DOMAIN` to its domain.

It's possible the CMS `Site Configuration` will be created through other means, but for completness:

- The `PREVIEW/LMS_BASE` values should be the parent domain of the Studio domain
- the `course_org_filter` should list the org that will exist on that `LMS_BASE` domain
    - This is how `View Live` and `Preview` get the domain to use
    - each org should only exist in _one_ CMS `Site Configuration`

### Optional Settings
The following settings are added in order to support redirecting to a default backend provider's end session endpoint.

See [here](https://openid.net/specs/openid-connect-session-1_0.html#RedirectionAfterLogout) for more information (section 5 and 5.1).

- `TPA_LOGOUT_PROVIDER` = 'keycloak'
    - If not set, the default logout behavior is maintained
    - Default: `None`
    - If set to a backend name, it will retrieve that provider for the current site and then attempt to redirect to the value in that providers `other_settings['END_SESSION_URL']` endpoint after performing normal logout

If there is no `END_SESSION_URL` entry on the provider, default logout behavior will be performed.

The following are only relevant if `TPA_LOGOUT_PROVIDER` is set to a backend name. These settings will control a query string that can be appended to the end session url and provide a redirect after loggout out of the OP.

Query string format: `<TPA_POST_LOGOUT_REDIRECT_FIELD>=<TPA_POST_LOGOUT_REDIRECT_URL>`

- `TPA_POST_LOGOUT_REDIRECT_FIELD` = 'redirect_uri'`
    - Query string field name for post logout redirect from OP
    - Default: `redirect_uri`
- `TPA_POST_LOGOUT_REDIRECT_URL = 'https://your.domain.com'`
    - Url for post logout redirect from OP
    - Default: `current_site`
    - If set to `None`, then no redirect URI query string will be added to the end session endpoint

- `TPA_ENABLE_OP_SESSION_MANAGEMENT = True/False`
    - If enabled, adds the check session iframe to the LMS/CMS
    - This will log the user out of edx if their session status changes on the OP.
    - This will occur for users who have logged in after the setting is enabled.
