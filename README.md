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
    - Add `store_logout_url` and `check_session_management` to pipeline
- Updates the `Sign Out` link in the CMS to use the user's LMS root url as its logout url

The requirement still holds that the `slug` must match the `backend_name` of the `OAuth2ProviderConfig`. This is automatically done when configuring with the external API.

The original edx implementation exists on the `base-edx-implementation` branch, so a diff can always be done there to see what has changed.

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
    - Set `ENABLE_THIRD_PARTY_AUTH = True` and save
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

### CMS Template Update
**Note:** This requires the [cms theming engine](https://gitlab.com/iblstudios/iblx-cms/) to be installed.

In order for the CMS to log the user out of the correct subdomain, it must know which domain to redirect the user to for logout. This value is stored in a session variable: `logout_url`.

In order to put that into the `Sign Out` linke, we need to perform the following:
- copy `third_party_auth/templates/third_party_auth/header.html` to `/edx/app/edxapp/edx-platform/themes/iblx/cms/templates/`
- copy `third_party_auth/templates/third_party_auth/user_dropdown.html` to `/edx/app/edxapp/edx-platform/themes/iblx/cms/templates/`

Do this as the `edxapp` user or make sure to `chown` the files to `edxapp:edxapp` once moved.

**NOTE:** It may be better to try and fetch this from a site specific cofiguration in the future, falling back to `settings.FRONT_END_LOGOUT_URL` much like other configurations options do, as opposed to storing something in the session like is currently done.

### LMS and CMS Site Configurations
In order to allow SSO between the LMS and CMS, they must share the same session cookie. The only way to accomplish this is for the Studio to exist on a subdomain of the LMS. For example:

- LMS: `org1.some.domain.com`
- CMS: `studio.org1.some.domain.com`

There needs to be a `Site` and `Site Configuration` entry for both LMS and CMS. The `Site Configuration`s must both have a `SESSION_COOKIE_DOMAIN` value set to the LMS subdomain with a dot prefix, eg: `.org1.some.domain.com`. They must also use the same `SESSION_COOKIE_NAME` (which is `sessionid` by default, so you shouldn't need to change this).

When the `OAuth2ProviderConfig` is created via the API, it will automatically set the `SESSION_COOKIE_DOMAIN` properly for both the target LMS and CMS.

In order for Studio to function properly, the following attributes needs to exist in the CMS `Site Configuration`:

```json
{
  "site_domain":"studio.org1.your.domain",
  "SITE_NAME":"studio.org1.your.domain",
  "SESSION_COOKIE_DOMAIN":".org1.your.domain",
  "LMS_BASE":"org1.your.domain",
  "PREVIEW_LMS_BASE":"preview.org1.your.domain",
  "course_org_filter":[
    "org1"
  ]
}
```

It's possible the CMS `Site Configuration` will be created through other means, but for completness:

- The `PREVIEW/LMS_BASE` values should be the parent domain of the Studio domain
- `SESSION_COOKIE_DOMAIN` will be set properly when the API is executed
- the `course_org_filter` should list the orgs that will exist on that `LMS_BASE` domain
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

These values are only relevant if `TPA_LOGOUT_PROVIDER` is set to a backend name. These settings will control a query string that can be appended to the end session url and provide a redirect after loggout out of the OP.

Query string format: `<TPA_POST_LOGOUT_REDIRECT_FIELD>=<TPA_POST_LOGOUT_REDIRECT_URL>`

- `TPA_POST_LOGOUT_REDIRECT_FIELD` = 'redirect_uri'`
    - Query string field name for post logout redirect from OP
    - Default: `redirect_uri`
- `TPA_POST_LOGOUT_REDIRECT_URL = 'https://your.domain.com'`
    - Url for post logout redirect from OP
    - Default: `current_site`
    - If set to `None`, then no redirect URI query string will be added to the end session endpoint

- `TPA_ENABLE_OP_SESSION_MANAGEMENT = True/False`
    - If enabled, adds the check session iframe _to the LMS only_
        - *Not currently enabled for the CMS as there are some cross origin challenges to work through*
    - This will log the user out of edx if their session status changes on the OP.
    - This will occur for users who have logged in after the setting is enabled.
