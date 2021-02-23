import logging

from Cryptodome.PublicKey.RSA import importKey
from jwkest.jwk import RSAKey
from jwkest.jwt import JWT
from jwkest.jws import (
    JWS,
    BadSignature,
    NoSuitableSigningKeys
)

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
    pub_key_str = provider.get_setting("PUBLIC_KEY")
    payload = _check_signature(pub_key_str, token)

    # TODO: Fetch last id token for current user
    last_id_token = ''
    _check_iss_aud_iat(payload)
    _check_sub_sid(payload)
    _check_events_claim(payload)
    _check_nonce_not_present(payload)
    _check_jti(payload)
    _check_iss(last_id_token, payload)
    _check_sub(last_id_token, payload)
    _check_sid(last_id_token, payload)


def _check_signature(pub_key_str, token):
    """Validate JWT signature and return validated payload"""
    pub_key_str = _add_begin_end_key(pub_key_str)
    pub_key = RSAKey(key=importKey(pub_key_str))
    # NOTE: We don't have the kid of stored public key, so we
    # assume the kid from incoming token is for this key
    kid = JWT().unpack(token).headers['kid']
    pub_key.kid = kid

    try:
        # Signature checked here
        payload = JWS().verify_compact(token, keys=[pub_key])
    except (BadSignature, NoSuitableSigningKeys) as e:
        log.error(e)
        raise

    return payload


def _check_iss_aud_iat(payload):
    """Validate iss, aud and iat claims

    Step 3. Validate the iss, aud, and iat Claims in the same way they are
    validated in ID Tokens.
    """
    pass


def _check_sub_sid(payload):
    """Check for sub and/or sid claims

    Step 4. Verify that the Logout Token contains a sub Claim, a sid Claim,
        or both.
    """
    if not 'sub' in payload and not 'sid' in payload:
        raise JwtValidationError('Missing "sub" and "sid" from JWT. One must be present')


def _check_events_claim(payload):
    """Validate events claim

    Step 5. Verify that the Logout Token contains an events Claim whose value
    is JSON object containing the member name
    http://schemas.openid.net/event/backchannel-logout.
    """
    claim = 'http://schemas.openid.net/event/backchannel-logout'
    events = payload.get('events', None)

    if events is None:
        raise JwtValidationError("Payload is missing 'events' claim")

    if not isinstance(events, dict):
        raise JwtValidationError(
            "'events' claim must be a JSON object. Got {}", type(events))

    if claim not in events:
        raise JwtValidationError(
            "JWT must contain {} claim, but it is missing".format(claim))

    if not isinstance(events[claim], dict):
        raise JwtValidationError(
            '{} claim must contain a json object'.format(claim))


def _check_nonce_not_present(payload):
    """Ensure nonce is _not_ present in claims

    Step 6. Verify that the Logout Token does not contain a nonce Claim.
    """
    if 'nonce' in payload:
        raise JwtValidationError(
            "Nonce claim found in payload, but should not be present")


def _check_jti(payload):
    """Check if jti claim was recently used

    Step 7. Optionally verify that another Logout Token with the same jti value
    has not been recently received.
    """
    pass


def _check_iss(last_id_token, payload):
    """Check that iss matches iss in current session's id token

    Step 8. Optionally verify that the iss Logout Token Claim matches the iss
    Claim in an ID Token issued for the current session or a recent session of
    this RP with the OP.
    """
    pass


def _check_sub(last_id_token, payload):
    """Check that sub matches sub from current session's id token

    Step 9. Optionally verify that any sub Logout Token Claim matches the sub
    Claim in an ID Token issued for the current session or a recent session of
    this RP with the OP.
    """

def _check_sid(last_id_token, payload):
    """Check that sid matches sid in most recent id_token

    Step 10. Optionally verify that any sid Logout Token Claim matches the sid
    Claim in an ID Token issued for the current session or a recent session of
    this RP with the OP.
    """
    pass
