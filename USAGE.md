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
- In the `Valid redirect URIs` field, create the following entries for the LMS and CMS:
    - `https://lms.domain.com/*`
    - `https://studio.domain.com/*`
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
        - `end_session_endpoint`
        - `check_session_iframe`
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
- Set the domain to `your.studio.domain.com`
- Set the display name to the same value as the domain
- Click Save
- Click `Home` in the upper left to navigate back to the main Django admin page
- Select `Site Configuration` under the `SITE_CONFIGURATION` header
- Click `ADD SITE CONFIGURATION` in the upper right
- Select the `your.studio.domain.com` site that you just created in the `Site` dropdown
- Check `Enabled`
- In the `Values` field, copy the following json, updating it appropriately:

```json
{
  "site_domain": "your.studio.domain.com",
  "SITE_NAME": "your.studio.domain.com",
  "SESSION_COOKIE_DOMAIN": "your.studio.domain.com",
  "LMS_BASE": "your.lms.domain.com",
  "PREVIEW_LMS_BASE": "preview.your.lms.domain.com",
  "PLATFORM_NAME":"Your Org Name",
  "course_org_filter": [
    "<your_org_short_name>"
  ],
  "is_cms": true
}
```

This is an example filled in for the cms domain: `studio.example.domain.com` with org short name `org1` and :

```json
{
  "site_domain": "example.studio.domain.com",
  "SITE_NAME": "example.studio.domain.com",
  "SESSION_COOKIE_DOMAIN": "example.studio.domain.com",
  "LMS_BASE": "lms.example.domain.com",
  "PREVIEW_LMS_BASE": "preview.example.domain.com",
  "PLATFORM_NAME":"Organization1",
  "course_org_filter": [
    "org1"
  ],
  "is_cms": true
}
```

Finally, click the `Save` button.

Each LMS and CMS must have a Site Configuration. The `SESSION_COOKIE_DOMAIN` for each one should be set to their own sites domain.

**NOTE:** After this process is complete, any user that previously accessed these sites will need to clear their cookies for those sites! Otherwise there may be existing cookies that cause conflicts. You can double check proper function by using a new incognito/private browsing window.

## API
In order to use the API, your client must first obtain an access token for the client you created in the previous step, [above](#oauth2-setup). Once you have obtained the access token, use it with the `Authorization: Bearer <token>` header to access the API.

For supporting multiple keycloak realms, use **keycloak** for `backend_name` in the URLS below.

The following endpoints are active in this implementation:

### List Configurations for Backend
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

### Get Details about Specific Configuration
- **GET:** `/api/third_party_auth/v0/oauth-providers/{backend_name}/{id}`
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

### Create-Update Backend Configuration
- **POST:** `/api/third_party_auth/v0/oauth-providers/{backend_name}/`
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

- **NOTE:** The `site` must already exist on edx in order to create a configuration for that domain.

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

## Onboarding A New Domain
Once you have an OAuth2 token and can access the API, complete the following steps for each domain:

In the Django admin:
- Ensure a `Site` object is created for the domain
- Create a `Site Configuration` that references the `Site` object

```json
{
  "site_domain": "lms.example.domain.com",
  "SITE_NAME": "lms.example.domain.com",
  "SESSION_COOKIE_DOMAIN": "lms.example.domain.com",
  "PREVIEW_LMS_BASE": "preview.lms.example.domain.com",
  "PLATFORM_NAME":"Organization1",
  "course_org_filter": [
    "org1"
  ],
}
```

- Use the [Create-Update](#create-updatebackendconfiguration) API to setup keycloak for that realm and domain
- If the site is a CMS (Studio), add `"is_cms": true` to the Site Configuration json
- The `SESSION_COOKIE_DOMAIN` should be set to the sites domain

This process needs to be repeated for each `LMS` and `CMS` domain that exists.

## Notes about SSO Flow
- When performing user onboarding through the [user-management API](https://docs.ibleducation.com/cisco/docs/ibl-user-api/), please make sure to add `"provider": "keycloak"` to the payload
    - The users full name must also be provided as that is a required field for EdX
- This will ensure an entry gets created for this user and backend in the django admin's `User Social Auth` table
- If this is not done during onboarding, when the user logs in they will be presented with a dialog asking them to link their account
- Please ensure users's are onboarded to edx _before_ they try and login to the LMS/CMS.
    - Logging into the LMS could present the user with additional fields to fill out, depending on what's passed via the id token
    - Logging into the CMS first will result in a "Page Not Found" because it will try to redirect to a `registration` url


