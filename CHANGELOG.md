# ChangeLog

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
