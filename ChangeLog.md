# ChangeLog

## 1.1.0 - 2021/03/10
- Adds a OIDC backchannel logout endpoint to `/auth/backchannel_logout/<backend>`
- Adds `IBL_CMS_PREVENT_CONCURRENT_LOGINS` setting to CMS `common.py`
- Registers signal handlers for login/logout to set/clear `cms_session_id` in user profile meta (like LMS does)
    - Only happens if `IBL_CMS_PREVENT_CONCURRENT_LOGINS` is true

## 1.0.0 - Initial Release
