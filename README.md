# Cisco-Third-Party-Auth
This is a modification to the base edx `third_party_auth` application to support multiple instances of the same backend.

Updates to this package also add support for dynamically modifying the `OAuth2ProviderConfigs` through OAuth2 Protected API endpoints.

## Changes
The following are the major changes made to the edx base application:
- In `models.OAuth2ProviderConfig` we set `KEYS = ('slug', 'site_ide')`
    - This means the current configuration is keyed off the `slug` and `site`, so we can use the same backend for different sites
        - Examples: `('keycloak', 'org1.domain.com'), ('keycloak', 'org2.domain.com')`
- In `provider.py` we modify the `Registry` class (where necessary) to fetch items based on the `slug`/`backend.name` and the `site.id`
- In `strategy.py` we fetch items based on the `slug`/`backend.name` and `site.id`

The requirement still holds that the `slug` must match the `backend_name` of the `OAuth2ProviderConfig`

The original edx implementation exists on the `base-edx-implementation` branch, so a diff can always be done there to see what has changed.

## Test Updates
I made minor updates to the tests:
- updated expected `provider_id` values where necessary since that's composed of `KEYS` which used to be slug only and is now `slug`, `site_id`
- Instead of the Base test creating a new site, I have it fetch `Site.objects.all()[0]`
    - When `KEYS` was just `('slug',)`, it didn't matter which site was used. It's applied to the whole platform
    - In our case, the provider site needs to match the requests site

With these changes, all tests pass as they did before.

## Installation
TBD

## EdX Setup
TBD

## KeyCloak Setup
TBD

## API
The following endpoints are active in this implementation:
- **GET:**: `/api/third_party_auth/v0/oauth-providers/{backend_name}/`
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

- **GET:**: `/api/third_party_auth/v0/oauth-providers/{backend_name}/<pk>`
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

- **POST:**: `/api/third_party_auth/v0/oauth-providers/{backend_name}`
    - Create a new configuration
    - The `OAuth2ProviderConfig` subclasses `ConfigurationModel` which means you can't actually _update_ or _delete_ a given configuration. You can only create new configurations which will override old ones
    - In this case, there can only be **one** active configuration for each `('slug', 'site_id')`, so when you create a new configuration if one exists for the given `slug` and `site_id`, the one you create will become the new active configuration
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
