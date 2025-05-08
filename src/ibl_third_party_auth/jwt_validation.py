import logging
import time

import jwt
from Cryptodome.PublicKey.RSA import importKey
from social_django.models import UserSocialAuth

log = logging.getLogger(__name__)

BEGIN_KEY = "-----BEGIN PUBLIC KEY-----"
END_KEY = "-----END PUBLIC KEY-----"


class JwtValidationError(Exception):
    pass


def _add_begin_end_key(pub_key):
    """Add the begin/end prefix to public key"""
    if not pub_key.startswith(BEGIN_KEY):
        return "{}\n{}\n{}".format(BEGIN_KEY, pub_key, END_KEY)
    return pub_key


def validate_jwt(provider, token):
    """Validate JWT and return payload

    https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation
    """

    options = {
        "require_exp": False,
        "require_iat": True,
        "verify_iat": True,
        "verify_aud": True,
        "verify_iss": True,
        "verify_signature": True,
    }
    public_key = _add_begin_end_key(provider.get_setting("PUBLIC_KEY"))
    aud = provider.key
    payload = jwt.decode(
        token,
        key=public_key,
        verify=True,
        options=options,
        issuer=provider.get_setting("ISS"),
        audience=aud,
        algorithms=["RS256"],
    )
    _check_nonce_not_present(payload)
    # jwt.decode doesn't validate awt slack, only that it's an int
    _check_iat(payload["iat"])
    _check_jti(payload)
    _check_sub_sid(payload)
    _check_events_claim(payload)
    # _perform_optional_checks(provider, payload)

    return payload


def _perform_optional_checks(pub_key_str, provider, payload):
    """Optional checks against previously issued id_token"""
    try:
        # social_auth = UserSocialAuth.objects.get(uid=payload['sub'])
        social_auth = UserSocialAuth.objects.get(user__username="common@user.com")
    except UserSocialAuth.DoesNotExist:
        raise JwtValidationError("Unable to find Social Auth User: %s", payload["sub"])

    # last_id_token = _check_signature(
    #     pub_key_str, social_auth.extra_data.get('id_token'))
    #
    # # These are optional checks, which could cause issues
    # _check_last_iss(last_id_token, payload)
    # _check_last_sub(last_id_token, payload)
    # _check_last_sid(last_id_token, payload)


def _check_iat(iat, slack=120):
    """Validate iat claim

    Args:
        iat (int): Time token was created
        slack (int): Max seconds in past token must have been created
    """
    now = int(time.time())
    if (now - iat) > slack:
        raise JwtValidationError(
            "Token created too long in the past (%ss ago > %s); rejecting",
            now - iat,
            slack,
        )


def _check_sub_sid(payload):
    """Check for sub and/or sid claims

    Step 4. Verify that the Logout Token contains a sub Claim, a sid Claim,
        or both.
    """
    if not "sub" in payload and not "sid" in payload:
        raise JwtValidationError(
            'Missing "sub" and "sid" from JWT. One must be present'
        )


def _check_events_claim(payload):
    """Validate events claim

    Step 5. Verify that the Logout Token contains an events Claim whose value
    is JSON object containing the member name
    http://schemas.openid.net/event/backchannel-logout.
    """
    claim = "http://schemas.openid.net/event/backchannel-logout"
    events = payload.get("events", None)

    if events is None:
        raise JwtValidationError("Payload is missing 'events' claim")

    if not isinstance(events, dict):
        raise JwtValidationError(
            "'events' claim must be a JSON object. Got {}", type(events)
        )

    if claim not in events:
        raise JwtValidationError(
            "JWT must contain {} claim, but it is missing".format(claim)
        )

    if not isinstance(events[claim], dict):
        raise JwtValidationError("{} claim must contain a json object".format(claim))


def _check_nonce_not_present(payload):
    """Ensure nonce is _not_ present in claims

    Step 6. Verify that the Logout Token does not contain a nonce Claim.
    """
    if "nonce" in payload:
        raise JwtValidationError(
            "Nonce claim found in payload, but should not be present"
        )


def _check_jti(payload):
    """Check if jti claim was recently used

    Step 7. Optionally verify that another Logout Token with the same jti value
    has not been recently received.
    """
    log.debug("Checking of jti is optional; not currently checking")


def _check_last_iss(last_id_token, payload):
    """Check that iss matches iss in current session's id token

    Step 8. Optionally verify that the iss Logout Token Claim matches the iss
    Claim in an ID Token issued for the current session or a recent session of
    this RP with the OP.
    """
    log.debug("Checking last iss is optional; not currently checking")


def _check_last_sub(last_id_token, payload):
    """Check that sub matches sub from current session's id token

    Step 9. Optionally verify that any sub Logout Token Claim matches the sub
    Claim in an ID Token issued for the current session or a recent session of
    this RP with the OP.
    """
    log.debug("Checking last sub is optional; not currently checking")


def _check_last_sid(last_id_token, payload):
    """Check that sid matches sid in most recent id_token

    Step 10. Optionally verify that any sid Logout Token Claim matches the sid
    Claim in an ID Token issued for the current session or a recent session of
    this RP with the OP.
    """
    log.debug("Checking last sid is optional; not currently checking")
