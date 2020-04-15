# Cisco-Third-Party-Auth
This document describes customer usage and required setup.

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

## Temporary CMS Site Setup
In order to share a session with the LMS, the studio must live on a subdomain of that LMS. These steps will be automated into the site creation API calls in the future, but until then the following steps must be taken:

- Open the django at `your.domain.com/admin` and login as a super user
- Select `Sites` under the `SITES` topic
- Click `ADD SITE` in the upper right
- Set the domain to `studio.your.lms.domain.com`
- Set the display name to `<Your Org> Studio`
- Click Save
- Click `Home` in the upper left to navigate back to the main Django admin page
- Select `Site Configuration` under the `SITE_CONFIGURATION` header
- Click `ADD SITE CONFIGURATION` in the upper right
- Select the `studio.your.lms.domain.com` site that you just created in the `Site` dropdown
- Check `Enabled`
- In the `Values` field, copy the following json, updating it appropriately:

```json
{
  "site_domain": "studio.your.lms.domain.com",
  "SITE_NAME": "studio.your.lms.domain.com",
  "SESSION_COOKIE_DOMAIN": ".your.lms.domain.com",
  "LMS_BASE": "your.lms.domain.com",
  "PREVIEW_LMS_BASE": "preview.your.lms.domain.com",
  "course_org_filter": [
    "<your_org_short_name>"
  ]
}
```

**Note:** Notice the leading `.` in the `SESSION_COOKIE_DOMAIN`! It is critical.

This is an example filled in for the lms domain: `organization1.example.domain.com` for org short name `org1`:

```json
{
  "site_domain": "studio.organization1.example.domain.com",
  "SITE_NAME": "studio.organization1.example.domain.com",
  "SESSION_COOKIE_DOMAIN": ".organization1.example.domain.com",
  "LMS_BASE": "organization1.example.domain.com",
  "PREVIEW_LMS_BASE": "preview.organization1.example.domain.com",
  "course_org_filter": [
    "org1"
  ]
}
```

Finally, click the `Save` button.

We now need to make sure the `SESSION_COOKIE_DOMAIN` value for the LMS Site Configuration matches the one we just created.

- Go back to the list of `Site Configuration` entries
- Click the _LMS_ domain that corresponds to the parent domain of the studio you just created
    - eg, if you just created `studio.organization1.domain.com`, click `organization1.domain.com`
- Add or update the `SESSION_COOKIE_DOMAIN` value to match that of the current domain with a leading `.`
    - So if the current domain is `organization1.example.domain.com`, it should be `.organization1.example.domain.com`
- Click `Save`

This process needs to be repeated for each LMS - CMS pair.

**NOTE:** After this process is complete, any user that previously accessed these sites will need to clear their cookies for those sites! Otherwise there may be existing cookies that cause conflicts. You can double check proper function by using a new incognito/private browsing window.

## API
In order to use the API, your client must first obtain an access token for the client you created in the previous step, [above](#oauth2-setup). Once you have obtained the access token, use it with the `Authorization: Bearer <token>` header to access the API.

For supporting multiple keycloak realms, use **keycloak** for `backend_name` in the URLS below.

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
        "END_SESSION_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/logout"
    },
    "secret": "some-secret-value",
    "site": "your.domain.com",
    "change_date": "2020-04-09T17:13:13.319589Z",
    "name": "Your Org"
}
```

- **POST:** `/api/third_party_auth/v0/oauth-providers/{backend_name}/`
    - Create a new configuration for a given backend and site
        - **NOTE:** The `site` and `CMS_SITE` must already exist on edx in order to create a configuration for that combination.
    - The payload must be `application/json` formatted as follows:

```json
{
    "name": "Org Display Name",
    "enabled": true,
    "client_id": "your client id",
    "secret": "your client credentials secret",
    "other_settings": {
        "PUBLIC_KEY": "auth-servers public key (no begin/end clauses, just key string)",
        "CHECK_SESSION_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/login-status-iframe.html",
        "AUTHORIZATION_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/auth",
        "ACCESS_TOKEN_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/token",
        "TARGET_OP": "https://your.keycloak.com",
        "END_SESSION_URL": "https://your.keycloak.com/auth/realms/your_org/protocol/openid-connect/logout"

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

The `client_id`, `secret`, and values from `other_settings` can be found on keycloak as described in the [Finding Links and Information](#finding-links-and-information) section.

The response will be the created object, just like the contents returned from the `detail` endpoint.