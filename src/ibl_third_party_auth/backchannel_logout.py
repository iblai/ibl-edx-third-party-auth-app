import logging
import time
from importlib import import_module

import jwt
from common.djangoapps.third_party_auth import provider
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_out
from django.http import HttpResponse
from social_django.models import UserSocialAuth

from . import jwt_validation

log = logging.getLogger(__name__)
SESSIONS_ENGINE = import_module(settings.SESSION_ENGINE)


def _get_user_from_sub(sub, backend):
    """Return the Django User based on sub from token

    Args:
        sub (str): subject id from token
        backend (str): OAuth backend name

    Returns:
        django.contrib.auth.User: User with UserSocialAuth.uid = username
    """
    # NOTE: This sub format represents a federated user from keycloak
    username = sub.split(":")[-1]
    social_auth = UserSocialAuth.objects.select_related("user__profile").get(
        uid=username, provider=backend
    )
    return social_auth.user


def _get_backchannel_logout_response(status):
    """Return an HttpResponse with status code and proper headers set

    https://openid.net/specs/openid-connect-backchannel-1_0.html#BCResponse
    """
    response = HttpResponse(status=status)
    response["Cache-Control"] = "no-cache, no-store"
    response["Pragma"] = "no-cache"
    return response


def _flush_session(store, meta_session_name, session_key):
    """Flush session_key and return True if not found in cache

    Args:
        store (SessionStore): A general session store not tied to a session_key
        meta_sssion_name (str): key from user meta that stores the session
        session_key (str): session key to delete
    """
    user_store = SESSIONS_ENGINE.SessionStore(session_key=session_key)
    user_store.flush()
    log.info("Flushed %s %s", meta_session_name, session_key)
    return store.exists(session_key)


def _logout_of_sessions(user, request):
    """Log user our of all sessions and emit a user_logged_out signal

    NOTE: "session_id" is the LMS session, "cms_session_id" is for the CMS

    Args:
        sessions (dict): {'session_name': 'session_id', ...}
        user (django.contrib.auth.User): Django User
        request (Request): Django request
    """
    meta = user.profile.get_meta()
    # meta keys that contain session_id's
    keys = ["session_id", "cms_session_id"]
    sessions = {key: meta.get(key) for key in keys}

    store = SESSIONS_ENGINE.SessionStore()
    session_exists = {
        key: store.exists(session_id) for key, session_id in sessions.items()
    }
    has_session = any(session_exists.values())

    # notify of logout - maybe not point though since audit log looks at
    # request.user which is None
    if has_session:
        user_logged_out.send(sender=user.__class__, request=request, user=user)
    else:
        log.warning("No active sessions exist for user %s", user.id)
        return

    # Delete sessions and remove them from profile meta
    # Have seen occurrences where says it's deleted, but then still exists in cache
    # So we will try up to three times
    attempts = 3
    profile = user.profile
    for name, session_id in sessions.items():
        if session_exists[name]:
            for idx in range(1, attempts + 1):
                still_exists = _flush_session(store, name, session_id)
                if still_exists:
                    log.info(
                        "Session %s still exists after %s attempts; sleeping 0.1",
                        session_id,
                        idx,
                    )
                    time.sleep(0.1)
                else:
                    log.info("Session %s no longer found", session_id)
                    break

            meta[name] = None

    profile.set_meta(meta)
    profile.save()


def _get_current_provider(backend):
    """Return the provider for the current site"""
    providers = list(provider.Registry.get_enabled_by_backend_name(backend))
    if not providers or len(providers) > 1:
        raise ValueError(
            "No or Multiple active providers found: {}".format(len(providers))
        )
    oauth_provider = providers[0]
    return oauth_provider


def back_channel_logout(request, backend):
    """Back Channel logout"""
    token = request.POST.get("logout_token")
    if not token:
        return _get_backchannel_logout_response(400)

    try:
        oauth_provider = _get_current_provider(backend)
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
        user = _get_user_from_sub(payload["sub"], backend)
        log.info("Backchannel logout request received for user %s", user.id)
    except UserSocialAuth.DoesNotExist:
        log.error("No UserSocialAuth.uid exists for sub %s", payload["sub"])
        return _get_backchannel_logout_response(501)

    _logout_of_sessions(user, request)

    return _get_backchannel_logout_response(200)
