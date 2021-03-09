import logging
from importlib import import_module

import jwt

from django.conf import settings
from django.contrib.auth.signals import user_logged_out
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from social_django.models import UserSocialAuth

from third_party_auth import provider, jwt_validation

log = logging.getLogger(__name__)
SESSIONS_ENGINE = import_module(settings.SESSION_ENGINE)


def _get_user_from_sub(sub):
    """Return the user profile object from token sub"""
    email = sub.split(':')[-1]
    social_auth = UserSocialAuth.objects.select_related('user__profile').get(user__email=email)
    return social_auth.user


def _get_backchannel_logout_response(status):
    """Return an HttpResponse with status code and proper headers set

    https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse
    """
    response = HttpResponse(status=status)
    response['Cache-Control'] = 'no-cache, no-store'
    response['Pragma'] = 'no-cache'
    return response


def _logout_of_sessions(sessions, user, request):
    """Log user our of all sessions and emit a user_logged_out signal

    NOTE: "session_id" is the LMS session, "cms_session_id" is for the CMS

    Args:
        sessions (dict): {'session_name': 'session_id', ...}
        user (django.contrib.auth.User): Django User
        request (Request): Django request
    """
    store = SESSIONS_ENGINE.SessionStore()
    session_exists = {key: store.exists(session_id) for key, session_id in sessions.items()}
    has_session = any(session_exists.values())

    # notify of logout
    if has_session:
        user_logged_out.send(sender=user.__class__, request=request, user=user)
    else:
        log.warning(
            "Logout request sent for user %s but user has no active sessions",
            user.email)
        return

    profile = user.profile
    meta = profile.get_meta()
    for name, session_id in sessions.items():
        if session_exists[name]:
            meta[name] = None
            store.delete(session_id)
            log.info("Deleted Session %s %s", name, session_id)
    profile.set_meta(meta)
    profile.save()

def _get_current_provider():
    """Return the provider for the current site"""
    providers = list(provider.Registry.get_enabled_by_backend_name('keycloak'))
    if not providers or len(providers) > 1:
        raise ValueError("No or Multiple active providers found: %s", len(providers))
    oauth_provider = providers[0]
    return oauth_provider


def back_channel_logout(request):
    """Back Channel logout"""
    token = request.POST.get('logout_token')
    if not token:
        return _get_backchannel_logout_response(400)

    try:
        oauth_provider = _get_current_provider()
    except ValueError as e:
        log.error(e)
        return _get_backchannel_logout_response(501)

    # Validate jwt
    try:
        payload = jwt_validation.validate_jwt(oauth_provider, token)
    except (jwt.exceptions.InvalidTokenError, jwt_validation.JwtValidationError) as e:
        log.error(e)
        return _get_backchannel_logout_response(400)
    except Exception as e:
        log.error(e, exc_info=True)
        return _get_backchannel_logout_response(501)

    try:
        user = _get_user_from_sub(payload['sub'])
        profile = user.profile
    except UserSocialAuth.DoesNotExist:
        log.error("No UserSocialAuth exists for sub %s", payload['sub'])
        return _get_backchannel_logout_response(501)

    meta = profile.get_meta()
    # meta keys that contain session_id's
    keys = ['session_id', 'cms_session_id']
    session_ids = {key: meta.get(key) for key in keys}
    _logout_of_sessions(session_ids, user, request)

    return _get_backchannel_logout_response(200)