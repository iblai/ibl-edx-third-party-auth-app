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

The requirement still holds that the `slug` must match the `backend_name` of the `OAuth2ProviderConfig`

The original edx implementation exists on the `base-edx-implementation` branch, so a diff can always be done there to see what has changed.

## Test Updates
I made minor updates to the tests:
- updated expected `provider_id` values where necessary since that's composed of `KEYS` which used to be `slug` only and is now `slug`, `site_id`
- Instead of the Base test creating a new site, I have it fetch `Site.objects.all()[0]`
    - When `KEYS` was just `('slug',)`, it didn't matter which site was used. It's applied to the whole platform
    - In our case, the provider site needs to match the requests site

With these changes, all tests pass as they did before.

## Installation
This package is meant to replace the built in `edx_third_party` auth package.

- rename the `third_party_auth` directory in `edx-platform/lms/common/djangoapps/` to `third_party_auth_old`
- `sudo -Hu edxapp bash`
- `source /edx/app/edxapp/venvs/edxapp/bin/activate`
- `pip install git+https://gitlab.com/iblstudios/cisco-third-party-auth`

### Enabling Auto Login for SSO Keycloak
If you want to enable auto login for each domain to their keycloak realm:

- Follow installation instructions for installing the [ibl-tpa-middleware](https://gitlab.com/iblstudios/ibl-tpa-middleware) package
- Add it to the middleware
- Set `TPA_MIDDLEWARE_DEFAULT_PROVIDER = 'keycloak'` in `lms/envs/common.py`

## KeyCloak Setup
### New Realm Setup
To setup a new realm in KeyCloak and enable it for EdX, perform the following steps:

- Login to keycloak admin
- Hover over the realm name in the upper left and select `Add Realm`
- Give the realm a name **without spaces** and select `Create`
- Select `Roles` on the left
- Click `Add Role` in the upper right
- enter `user` as the name, and save

### Creating a New edX client
- With your realm active, select `Clients` on the left
- Click `Create` in the upper right
- enter the `Client ID` - can be `edx` for simplicity
- click `Save`
- Change `Access Type` to `confidential`
- Enter `https://edx.subdomain.com/auth/complete/keycloak/*` in the `Valid Redirect URI's` field
    - `edx.subdomain.com` corresponds to which edx subdomain this realm will be associated with
- Expand `Fin Grain OpenID Connect Configuration`
    - Change `User Info Signed Response Algorithm` to `RS256`
    - Change Request Object Signature Algorithm` to `RS256`
    - Select `Save`
- Click `Mappers` at the top
- Click `Add Builtin` in the upper right
    - Check `email`, `given name`, `family name, `username`
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
- Optionally check `Email Verified` if you don't want to require the user to verify their email
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
We must first enable third party auth in edx.

- Become the root `sudo -i`
- Open `edx-platform/lms/envs/common.py`
- Set `ENABLE_THIRD_PARTY_AUTH = True` and save
- Activate the venv: `source /edx/app/edxapp/venvs/edxapp/bin/activate`
- Navigate to `/edx/app/edxapp/edx-platform`
- Run: `./manage.py lms migrate third_party_auth --settings=production`
- Restart the lms: `/edx/bin/supervisorctl restart lms cms`

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
        "id": 99,
        "changed_by": "geoff-va",
        "client_id": "edx",
        "enabled": true,
        "other_settings": {
            "AUTHORIZATION_URL": "https://keycloak.cluster-v010.iblstudios.com/auth/realms/org2/protocol/openid-connect/auth",
            "PUBLIC_KEY": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq2cfbbhEmoHq/aZmuZD4COCzr+rNSzyS9t5Z4O804dWSPmcicJ0p9KPjW7WHW27+MMi9EJ7sAHaoRRnNMEw5ngD+Ap0T4Qf/KUyjQtExhmlVQDIATqEUgZdKYsfTJtJ1nP5jOJFmItKrGjMlHcLgtbPdCNnz/MU0mIevPhnYUGu0lEY0uEyTjuy2WEJw/i/HIf+UzNZXZZ/gED7h37gxDdwfsxP+G+FS5H17JICcTtmkjdx0S2BEj/Re12U/C8iu6Xm1OxHGTokQw2WwlLYodDO4Mnz+H02U0qsHX8l3IW22EPycP3NSzfSvuNatCPxjtninI0TpOfH+HRKFERYAPQIDAQAB",
            "ACCESS_TOKEN_URL": "https://keycloak.cluster-v010.iblstudios.com/auth/realms/org2/protocol/openid-connect/token"
        },
        "secret": "487faaa7-13c1-48f5-8280-96a453fae8b7",
        "site": "cluster-v023.iblstudios.com",
        "change_date": "2020-03-23T16:57:42.137570Z",
        "name": "Updated Org 3"
    },
    {
        "id": 68,
        "changed_by": null,
        "client_id": "",
        "enabled": false,
        "other_settings": {},
        "secret": "",
        "site": "org1.cluster-v023.iblstudios.com",
        "change_date": "2020-03-19T20:36:02.695510Z",
        "name": "Updated Org1"
    }
]
```

- **GET:** `/api/third_party_auth/v0/oauth-providers/{backend_name}/<pk>`
    - Returns detail about a specific configuration via it's primary key (id from list endpoint, above)

Example Response:
```json
{
    "id": 99,
    "changed_by": "geoff-va",
    "client_id": "edx",
    "enabled": true,
    "other_settings": {
        "AUTHORIZATION_URL": "https://keycloak.cluster-v010.iblstudios.com/auth/realms/org2/protocol/openid-connect/auth",
        "PUBLIC_KEY": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq2cfbbhEmoHq/aZmuZD4COCzr+rNSzyS9t5Z4O804dWSPmcicJ0p9KPjW7WHW27+MMi9EJ7sAHaoRRnNMEw5ngD+Ap0T4Qf/KUyjQtExhmlVQDIATqEUgZdKYsfTJtJ1nP5jOJFmItKrGjMlHcLgtbPdCNnz/MU0mIevPhnYUGu0lEY0uEyTjuy2WEJw/i/HIf+UzNZXZZ/gED7h37gxDdwfsxP+G+FS5H17JICcTtmkjdx0S2BEj/Re12U/C8iu6Xm1OxHGTokQw2WwlLYodDO4Mnz+H02U0qsHX8l3IW22EPycP3NSzfSvuNatCPxjtninI0TpOfH+HRKFERYAPQIDAQAB",
        "ACCESS_TOKEN_URL": "https://keycloak.cluster-v010.iblstudios.com/auth/realms/org2/protocol/openid-connect/token"
    },
    "secret": "487faaa7-13c1-48f5-8280-96a453fae8b7",
    "site": "cluster-v023.iblstudios.com",
    "change_date": "2020-03-23T16:57:42.137570Z",
    "name": "Updated Org 3"
}
```

- **POST:** `/api/third_party_auth/v0/oauth-providers/{backend_name}`
    - Create a new configuration for a given backend and site
        - **NOTE:** The `Site` must already exist on edx in order to create a configuration for it
    - The `OAuth2ProviderConfig` subclasses `ConfigurationModel` which means you can't actually _update_ or _delete_ a given configuration. You can only create new configurations which will override old ones
    - In this case, there can only be **one** active configuration for each `('slug', 'site_id')`, so when you create a new configuration if one exists for the given `slug` and `site_id`, the one you create will become the new active configuration
        - **NOTE:** `slug` is the same as the `backend_name` since they must be the same, eg: `keycloak` or `google-oauth2`, `facebook`, etc.
    - The payload should look something like the following:

```json
{
	"name": "Config Name",
	"enabled": true,
	"client_id": "edx",
	"secret": "487faaa7-13c1-48f5-8280-96a453fae8b7",
	"other_settings": {
		"PUBLIC_KEY": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq2cfbbhEmoHq/aZmuZD4COCzr+rNSzyS9t5Z4O804dWSPmcicJ0p9KPjW7WHW27+MMi9EJ7sAHaoRRnNMEw5ngD+Ap0T4Qf/KUyjQtExhmlVQDIATqEUgZdKYsfTJtJ1nP5jOJFmItKrGjMlHcLgtbPdCNnz/MU0mIevPhnYUGu0lEY0uEyTjuy2WEJw/i/HIf+UzNZXZZ/gED7h37gxDdwfsxP+G+FS5H17JICcTtmkjdx0S2BEj/Re12U/C8iu6Xm1OxHGTokQw2WwlLYodDO4Mnz+H02U0qsHX8l3IW22EPycP3NSzfSvuNatCPxjtninI0TpOfH+HRKFERYAPQIDAQAB",
		"AUTHORIZATION_URL": "https://keycloak.cluster-v010.iblstudios.com/auth/realms/org2/protocol/openid-connect/auth",
		"ACCESS_TOKEN_URL": "https://keycloak.cluster-v010.iblstudios.com/auth/realms/org2/protocol/openid-connect/token"

	},
	"site": "cluster-v023.iblstudios.com"
}
```

The `client_id`, `secret`, and values from `other_settings` can be found on keycloak as described in the [Finding Links and Information](#finding-links-and-information) section.

The response will be the created object, just like the contents returned from the `detail` endpoint.
