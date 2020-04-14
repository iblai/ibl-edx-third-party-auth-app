# Cisco-Third-Party-Auth
This is a modification to the base edx `third_party_auth` application to support using variations of the same provider on each subdomain. This was built specifically with `KeyCloak` in mind to support a different realm on each subdomain.

Updates to this package also add support for dynamically modifying the `OAuth2ProviderConfigs` through OAuth2 Protected API endpoints.

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

### Enabling Auto Login for SSO Keycloak
If you want to enable auto login for each domain to their keycloak realm:

- Follow installation instructions for installing the [ibl-tpa-middleware](https://gitlab.com/iblstudios/ibl-tpa-middleware) package
- Add it to the middleware as the second to last entry (leave `SessionCookieDomainOverrideMiddleware` at the end)
- Set `TPA_MIDDLEWARE_DEFAULT_PROVIDER = 'keycloak'` in `lms/envs/common.py`

## KeyCloak Setup
### New Realm Setup
To setup a new realm in KeyCloak and enable it for EdX, perform the following steps:

- Login to keycloak admin
- Hover over the realm name in the upper left and select `Add Realm`
- Give the realm a name **without spaces** and select `Create`

### Creating a New edX client
- With your realm active, select `Clients` on the left
- Click `Create` in the upper right
- enter the `Client ID` - can be `edx` for simplicity
- click `Save`
- Change `Access Type` to `confidential`
- In the `Valid redirect URIs` field, enter:
    - `https://edx.subdomain.com/auth/complete/keycloak/*`
    - `https://edx.subdomain.com`
- In `Web Origins` add `+` (literally, just a `+` symbol)
- Expand `Fine Grain OpenID Connect Configuration`
    - Change `User Info Signed Response Algorithm` to `RS256`
    - Change `Request Object Signature Algorithm` to `RS256`
    - Select `Save`
- Click `Mappers` at the top
- Click `Add Builtin` in the upper right
    - Check `email`, `username` (modify as required, `email`, `username` are required though)
    - Click `Add Selected`
- On that same `Mappers` tab, click `Create`
    - Set `Name` to `Audience`
    - `Mapper Type` to `Audience`
    - Under `Included Client Audience` select the client name you created (`edx`)
    - Click `Save`

### Creating New Users
To create new users in KeyCloak:
- Select `Users` on the left
- Fill out the appropriate information - specifically username and email at a minimum
- Save the user

### Finding Links and Information
You will need various information in edx from the keycloak realm. First make sure the appropriate realm is selected, then information can be found as follows:

- URLs:
    - Select `Realm Settings` on the left
    - Click the `OpenID Endpoint Configuration` link under `Endpoints`
    - Here you will find any and all URLs necessary
    - Specifically:
        - `authorization_endpoint`
        - `token_endpoint`
        - TODO: `end_session_endpoint` ?
- OAuth2 Credentials:
    - Select `Clients` on the left
    - Select the `edx` client (or whatever you named it)
    - `client_id` is shown in the `Client ID` field
    - The secret is under the `Credentials` tab at the top, then in the `secret` field
- Public Key:
    - Select `Realm Settings` on the left
    - Select the `Keys` tab at the top
    - Click the `Public Key` button next to the RSA key and it will display the public key for the current realm

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

### CMS Template Update
**Note:** This requires the [cms theming engine](https://gitlab.com/iblstudios/iblx-cms/) to be installed.

In order for the CMS to log the user out of the correct subdomain, it must know which domain to redirect the user to for logout. This value is stored in a session variable: `logout_url`.

In order to put that into the `Sign Out` linke, we need to perform the following:
- copy `third_party_auth/templates/third_party_auth/header.html` to `/edx/app/edxapp/edx-platform/themes/iblx/cms/templates/`
- copy `third_party_auth/templates/third_party_auth/user_dropdown.html` to `/edx/app/edxapp/edx-platform/themes/iblx/cms/templates/`

Do this as the `edxapp` user or make sure to `chown` the files to `edxapp:edxapp` once moved.

**NOTE:** We should probably find a more robust way to do this in the future.

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
    "edX"
  ]
}
```

It's possible the CMS `Site Configuration` will be created through other means, but for completness:

- The `PREVIEW/LMS_BASE` values should be the parent domain of the Studio domain
- `SESSION_COOKIE_DOMAIN` will be set properly when the API is executed
- the `course_org_filter` should list the orgs that will exist on that `LMS_BASE` domain
    - This is how `View Live` and `Preview` get the domain to use
    - each org should only exist in _one_ CMS `Site Configuration`

### OAuth2 Setup
In order to use the OAuth2 Provider Configuration API endpoints, we must create an `OAuth2` client for that user and the requesting application.

- Navigate to `your.edx.domain.com/admin`
- Login as a superuser
- Under the `OAuth2` heading, select `Clients`
- Click `Add Client` in the upper right
- Select the `User` that will associated with this access token
    - **NOTE:** This user _must_ have `is_superuser = True` privileges
- Give the client an identifying name (`OAuth2ProviderConfig API`)
- Enter your applications `Url` and `Redirect Uri`
- Set the client type to `Confidential (Web Applications)`
- Click Save

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

## API
In order to use the API, your client must first obtain an access token for the client you created in the previous step, [above](#oauth2-setup). Once you have obtained the access token, use it with the `Authorization: Bearer <token>` header to access the API.

For supporting multiple keycloak realms, use `keycloak` for `backend_name` in the URLS below.

The following endpoints are active in this implementation:
- **GET:** `/api/third_party_auth/v0/oauth-providers/{backend_name}/`
    - Returns List of dicts that contain information about the backend

Example Response:
```json
[
    {
        "id": 1,
        "changed_by": "manager",
        "client_id": "edx",
        "enabled": true,
        "other_settings": {
            "PUBLIC_KEY": "auth server public key",
            "CHECK_SESSION_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/login-status-iframe.html",
            "AUTHORIZATION_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/auth",
            "ACCESS_TOKEN_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/token",
            "TARGET_OP": "https://your.keycloak.com",
            "END_SESSION_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/logout"
        },
        "secret": "some-secret-value",
        "site": "your.domain.com",
        "change_date": "2020-04-09T17:13:13.319589Z",
        "name": "Your Org"
    }
]
```

- **GET:** `/api/third_party_auth/v0/oauth-providers/{backend_name}/<pk>`
    - Returns detail about a specific configuration via it's primary key (id from list endpoint, above)

Example Response:
```json
{
    "id": 1,
    "changed_by": "manager",
    "client_id": "edx",
    "enabled": true,
    "other_settings": {
        "PUBLIC_KEY": "auth server public key",
        "CHECK_SESSION_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/login-status-iframe.html",
        "AUTHORIZATION_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/auth",
        "ACCESS_TOKEN_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/token",
        "TARGET_OP": "https://your.keycloak.com",
        "END_SESSION_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/logout",
        "CMS_SITE": "studio.org1.domain.com"
    },
    "secret": "some-secret-value",
    "site": "your.domain.com",
    "change_date": "2020-04-09T17:13:13.319589Z",
    "name": "Your Org"
}
```

- **POST:** `/api/third_party_auth/v0/oauth-providers/{backend_name}/`
    - Create a new configuration for a given backend and site
        - **NOTE:** The `Site` must already exist on edx in order to create a configuration for it
    - The `OAuth2ProviderConfig` subclasses `ConfigurationModel` which means you can't actually _update_ or _delete_ a given configuration. You can only create new configurations which will override old ones
    - In this case, there can only be **one** active configuration for each `('slug', 'site_id')`, so when you create a new configuration if one exists for the given `slug` and `site_id`, the one you create will become the new active configuration
        - **NOTE:** `slug` is the same as the `backend_name` since they must be the same, eg: `keycloak` or `google-oauth2`, `facebook`, etc.
    - The payload must be `application/json` formatted as follows:

```json
{
    "name": "Org Display Name",
    "enabled": true,
    "client_id": "your client id",
    "secret": "your client credentials secret",
    "other_settings": {
        "PUBLIC_KEY": "auth-servers public key (no begin/end clauses, just key string)",
        "AUTHORIZATION_URL": "https://your.auth.server.com/its-auth-endpoint",
        "ACCESS_TOKEN_URL": "https://your.auth.server.com/its-access-token-endpoint",
        "END_SESSION_URL": "https://your.auth.server.com/its-end-session-endpoint",
        "TARGET_OP": "https://your.auth.server.com",
        "CHECK_SESSION_URL": "https://devauth.netacad.com/auth/realms/Citizenschool/protocol/openid-connect/login-status-iframe.html",
        "CMS_SITE": "studio.org1.domain.com"

    },
    "site": "your.edx.subdomain.com"
}
```

Parameter definitons are as follows:
- `name`: A display name used in the django admin. Can just be the org name
- `enabled`: Whether or not to enable this SSO configuration for the site
- `client_id`: your OAuth2 client id
- `secret`: your OAuth2 secret
- `site`: the domain of the site this configuration applies to
- `PUBLIC_KEY`: the public key of the OP
- `AUTHORIZATION_URL`: auth url of OP
- `ACCESS_TOKEN_URL`: token url of OP
- `END_SESSION_URL`: the end session url of OP
- `TARGET_OP`: https://your.auth.server.com (protocol + auth server domain)
- `CHECK_SESSION_URL`: check session endpoint of OP. Allows RP to direct an iframe to this endpoint to check session status at the OP
- `CMS_SITE`: the domain of the studio - must be a subdomain of the `site` domain, eg: `studio.org1.domain.com` as subdomain of `org1.domain.com`

The `client_id`, `secret`, and values from `other_settings` can be found on keycloak as described in the [Finding Links and Information](#finding-links-and-information) section.

The response will be the created object, just like the contents returned from the `detail` endpoint.
