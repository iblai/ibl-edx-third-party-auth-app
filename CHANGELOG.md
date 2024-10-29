# ChangeLog

## 2.0.8
- Add automatic platform linking for Azure AD users:
  - Add signal handler to monitor social auth creation
  - Add utility functions for provider configuration management
  - Add management command for linking existing users to platforms
  - Add configurable AZURE_PROVIDER setting (defaults to 'azuread-oauth2')
  - Add platform key extraction from provider settings
  - Improve logging for platform linking process
  - Add error handling for platform linking failures
  - Add comprehensive test coverage:
    - Test provider configuration retrieval
    - Test platform key extraction
    - Test custom provider settings
    - Test management command functionality
    - Test signal handler behavior
    - Test error handling scenarios
    - Test provider filtering

## 2.0.7
- Improve Apple ID authentication logging and security:
  - Add consistent state value masking (showing first 8 characters)
  - Streamline authentication flow logging with clearer stage indicators
  - Improve error message clarity and descriptions
  - Switch to Django's cache framework for state management
  - Add verification of Redis cache backend
  - Add session fallback for state storage
  - Add state validation bypass option for debugging
  - Remove sensitive data from logs

## 2.0.6
- Fix for Apple ID authentication

## 2.0.5
- Enhance Apple ID authentication process:
  - Implement Redis-based state management using Open edX's cache configuration
  - Add more detailed logging for debugging authentication issues
  - Improve error handling in client secret generation and token decoding
  - Update tests to cover new Redis-based state management and error scenarios
  - Clean up logging to avoid exposing sensitive data
  - Fix client secret handling in token requests
  - Add state validation bypass option for debugging

## 2.0.4
- Add testing for Apple ID authentication
- New google JWT validation flow.
- Add support for multiple audiences.
- Add error logging.
- Remove openidconnect override.
- New provider util to get audiences from provider settings
- New Apple JWT validation flow.
- Add error logging
- New user util to create user and userprofile

## 2.0.3
- Update to the process_exception logging

## 2.0.1
- Add override for apple-id SSO flow

## 2.0.0 - 2021-06-15
- Adds KOA support
- No longer copies and modifies original app. Instead patches relevant portions of `common.djangoapps.third_party_auth` and adds our API's/changes where necessary.
- Drops all support for `check-session-iframe` content.
    - Removes `TARGET_OP` from provider `other_settings`
    - This no longer works due to browser related changes and third party cookie blocking (safari)
- Changes oidc provider `other_settings['END_SESSION_URL']` -> `logout_url`
    - `logout_url` is now a built in value that can be retrieved by edx, so we use it instead of creating our own key
- Removes `TPA_LOGOUT_PROVIDER` setting; no longer needed since we get `logout_url` from provider that user logged in under
- Removes `IBL_DISABLE_MARKETING_COOKIES` settings
    - This needs to be approached in a different way
- Renames `setup.py` app name to `ibl-third-party-auth`

## 1.1.1 - 2021-04-20
- Change from calling `store.delete(session_key)` to `store = SessionStore(session_key).flush()`
- Validate `store.exists(session_key)` returns False; try up to three times
    - Have seen instances in devlms where session was claimed to have been deleted but user remained logged in
    - This was very inconsistent to reproduce and have only been able to reproduce on devlms
    - That's using `cached_db` as the SessionStore engine instead of `cache` (typical deployment). Unsure if related, though.
- Adds `IBL_DISABLE_MARKETING_COOKIES` setting (default `True`).
    - If True, sets the methods that would set the `DEPRECATED_LOGGED_IN_COOKIE_NAMES` value to a no-op
        - `EDXMKTG_LOGGED_IN_COOKIE_NAME`
        - `EDXMKTG_USER_INFO_COOKIE_NAME`

## 1.1.0 - 2021-03-10
- Adds a OIDC backchannel logout endpoint to `/auth/back_channel_logout/<backend>`
- Adds `IBL_CMS_PREVENT_CONCURRENT_LOGINS` setting to CMS `common.py`
- Registers signal handlers for login/logout to set/clear `cms_session_id` in user profile meta (like LMS does)
    - Only happens if `IBL_CMS_PREVENT_CONCURRENT_LOGINS` is true
- `ISS` (issuer) is now required when in the `other_settings` field when setting up `Oauth Provider Configs`

## 1.0.2 - 2020-12-08
* Renames package `ibl-edx-third-party-auth`
* Add CHANGELOG.md
* Rename `CUSTOMER_USAGE.md` to `USAGE.md` to support `read.ibleducation.com`
* Move README changes section into ChangeLog
* Update `TPA` variables to be prepended with `IBL_*` in README

## 1.0.1 (Initial Release)
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

### Test Updates
Minor updates to the tests:
- Updated expected `provider_id` values where necessary since that's composed of `KEYS` which used to be `slug` only and is now `slug`, `site_id`
- Instead of the Base test creating a new site, I have it fetch `Site.objects.all()[0]`
    - When `KEYS` was just `('slug',)`, it didn't matter which site was used. It's applied to the whole platform
    - In our case, the provider site needs to match the requests site

With these changes, all tests pass as they did before.

Added one additional test in `test_provider.py` that tests multiple keycloak providers being enabled.
