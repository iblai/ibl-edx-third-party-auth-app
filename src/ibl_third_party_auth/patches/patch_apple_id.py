# Vendored from version 3.4.0 (9d93069564a60495e0ebd697b33e16fcff14195b)
# of social-core:
# https://github.com/python-social-auth/social-core/blob/3.4.0/social_core/backends/apple.py
#
# Additional changes:
#
# - Patch for JWT algorithms specification: eed3007c4ccdbe959b1a3ac83102fe869d261948
#
# v3.4.0 is unreleased at this time (2020-07-28) and contains several necessary
# bugfixes over 3.3.3 for AppleID, but also causes the
# TestShibIntegrationTest.test_full_pipeline_succeeds_for_unlinking_testshib_account
# test in common/djangoapps/third_party_auth/tests/specs/test_testshib.py to break
# (somehow related to social-core's change 561642bf which makes a bugfix to partial
# pipeline cleaning).
#
# Since we're not maintaining this file and want a relatively clean diff:
# pylint: skip-file
#
#
# social-core, and therefore this code, is under a BSD license:
#
#
# Copyright (c) 2012-2016, Matías Aguirre
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#     1. Redistributions of source code must retain the above copyright notice,
#        this list of conditions and the following disclaimer.
#
#     2. Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#
#     3. Neither the name of this project nor the names of its contributors may be
#        used to endorse or promote products derived from this software without
#        specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Sign In With Apple authentication backend.

Docs:
    * https://developer.apple.com/documentation/signinwithapplerestapi
    * https://developer.apple.com/documentation/signinwithapplerestapi/tokenresponse

Settings:
    * `TEAM` - your team id;
    * `KEY` - your key id;
    * `CLIENT` - your client id;
    * `AUDIENCE` - a list of authorized client IDs, defaults to [CLIENT].
                   Use this if you need to accept both service and bundle id to
                   be able to login both via iOS and ie a web form.
    * `SECRET` - your secret key;
    * `SCOPE` (optional) - e.g. `['name', 'email']`;
    * `EMAIL_AS_USERNAME` - use apple email is username is set, use apple id
                            otherwise.
    * `AppleIdAuth.TOKEN_TTL_SEC` - time before JWT token expiration, seconds.
    * `SOCIAL_AUTH_APPLE_ID_INACTIVE_USER_LOGIN` - allow inactive users email to
                                                   login
"""

import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Union

import jwt
from common.djangoapps.third_party_auth import appleid
from common.djangoapps.third_party_auth.appleid import AppleIdAuth
from django.conf import settings
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import PyJWTError
from social_core.exceptions import AuthFailed, AuthStateMissing
from social_django.models import UserSocialAuth

log = logging.getLogger(__name__)


def verify_redis_cache() -> bool:
    """Verify that Django's cache backend is Redis."""
    cache_backend = settings.CACHES.get("default", {}).get("BACKEND", "")
    if cache_backend == "django_redis.cache.RedisCache":
        log.info("Using Redis cache backend")
        return True
    else:
        log.warning(
            "Cache backend is not Redis", extra={"cache_backend": cache_backend}
        )
        return False


class IBLAppleIdAuth(AppleIdAuth):
    name = "apple-id"

    JWK_URL = "https://appleid.apple.com/auth/keys"
    AUTHORIZATION_URL = "https://appleid.apple.com/auth/authorize"
    ACCESS_TOKEN_URL = "https://appleid.apple.com/auth/token"
    ACCESS_TOKEN_METHOD = "POST"
    RESPONSE_MODE = None

    ID_KEY = "sub"
    TOKEN_KEY = "id_token"
    STATE_PARAMETER = True
    REDIRECT_STATE = False

    TOKEN_AUDIENCE = "https://appleid.apple.com"
    TOKEN_TTL_SEC = 6 * 30 * 24 * 60 * 60

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        log.info("Initializing Apple ID authentication")
        super().__init__(*args, **kwargs)
        verify_redis_cache()

    def auth_complete(self, *args: Any, **kwargs: Any) -> Any:
        """Complete the auth process."""
        log.info("Starting auth completion process")
        try:
            log.debug(
                "Auth completion parameters",
                extra={"args_length": len(args), "kwargs_keys": list(kwargs.keys())},
            )

            response = super().auth_complete(*args, **kwargs)
            log.info("Auth completion successful")
            return response
        except Exception as e:
            log.error(
                "Auth completion failed",
                extra={"error_type": type(e).__name__, "error_message": str(e)},
            )
            if hasattr(e, "response"):
                log.error(
                    "Auth response details",
                    extra={
                        "status_code": e.response.status_code,
                        "content": str(e.response.content),
                    },
                )
            raise

    def auth_params(
        self, state: Optional[str] = None, *args: Any, **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Apple requires to set `response_mode` to `form_post` if `scope`
        parameter is passed.
        """
        log.info("Generating auth parameters")
        params = super().auth_params(state=state, *args, **kwargs)

        if self.RESPONSE_MODE:
            params["response_mode"] = self.RESPONSE_MODE
        elif self.get_scope():
            params["response_mode"] = "form_post"

        # Store state in both cache and session
        if state:
            state_preview = f"{state[:8]}..." if state else None
            log.info("Storing auth state", extra={"state_preview": state_preview})
            try:
                session_key = self.strategy.session.session_key
                if not session_key:
                    self.strategy.session.create()
                    session_key = self.strategy.session.session_key

                cache_key = f"apple_auth_state:{session_key}"
                cache.set(cache_key, state, timeout=300)
                self.strategy.session["apple_auth_state"] = state

                # Verify storage
                stored_cache_state = cache.get(cache_key)
                stored_session_state = self.strategy.session.get("apple_auth_state")
                log.debug(
                    "State storage verification",
                    extra={
                        "cache_state_exists": bool(stored_cache_state),
                        "session_state_exists": bool(stored_session_state),
                    },
                )
            except Exception as e:
                log.error(
                    "Failed to store auth state",
                    extra={"error_type": type(e).__name__, "error_message": str(e)},
                )

        log.debug(
            "Generated auth parameters", extra={"params_keys": list(params.keys())}
        )
        return params

    def get_private_key(self) -> str:
        """Return contents of the private key file."""
        log.debug("Retrieving private key")
        return self.setting("SECRET")

    def generate_client_secret(self) -> str:
        """Generate a client secret for Apple ID authentication."""
        log.info("Generating client secret")
        now = int(time.time())
        client_id = self.setting("CLIENT")
        team_id = self.setting("TEAM")
        key_id = (
            settings.SOCIAL_AUTH_APPLE_ID_KEY
            if hasattr(settings, "SOCIAL_AUTH_APPLE_ID_KEY")
            else ""
        )
        private_key = self.get_private_key()

        headers = {"kid": key_id}
        payload = {
            "iss": team_id,
            "iat": now,
            "exp": now + self.TOKEN_TTL_SEC,
            "aud": self.TOKEN_AUDIENCE,
            "sub": client_id,
        }

        try:
            token = jwt.encode(
                payload, key=private_key, algorithm="ES256", headers=headers
            )
            log.info("Client secret generated successfully")
            return token
        except Exception as e:
            log.error(
                "Failed to generate client secret",
                extra={"error_type": type(e).__name__, "error_message": str(e)},
            )
            raise

    def get_apple_jwk(self, kid: Optional[str] = None) -> Union[str, List[str]]:
        """Return requested Apple public key or all available."""
        log.info("Retrieving Apple JWK", extra={"kid": kid})
        keys = self.get_json(url=self.JWK_URL).get("keys")

        if not isinstance(keys, list) or not keys:
            log.error("Invalid JWK response", extra={"keys_type": type(keys)})
            raise AuthFailed(self, "Invalid jwk response")

        if kid:
            matching_keys = [key for key in keys if key["kid"] == kid]
            if not matching_keys:
                log.error("No matching JWK found", extra={"kid": kid})
                raise AuthFailed(self, f"No matching key found for kid: {kid}")
            return json.dumps(matching_keys[0])
        else:
            return (json.dumps(key) for key in keys)

    def decode_id_token(self, id_token: str) -> Dict[str, Any]:
        """Decode and validate JWT token from apple and return payload."""
        log.info("Decoding ID token")
        if not id_token:
            log.error("Missing ID token")
            raise AuthFailed(self, "Missing id_token parameter")

        try:
            header = jwt.get_unverified_header(id_token)
            log.debug("Retrieved token header", extra={"header": header})

            if "kid" not in header:
                log.error("Missing kid in token header")
                raise AuthFailed(self, "Invalid id_token header (missing kid)")

            apple_jwk = self.get_apple_jwk(header["kid"])
            key = RSAAlgorithm.from_jwk(apple_jwk)

            audience = self.setting("AUDIENCE", [self.setting("CLIENT")])
            if not isinstance(audience, list):
                audience = [audience]

            log.debug("Decoding token with audience", extra={"audience": audience})

            return jwt.decode(
                id_token,
                key=key,
                audience=audience,
                algorithms=["RS256"],
            )
        except PyJWTError as e:
            log.error(
                "Failed to decode ID token",
                extra={"error_type": type(e).__name__, "error_message": str(e)},
            )
            raise AuthFailed(self, str(e))

    def get_user_fullname(self, email: str) -> Dict[str, str]:
        """Get user's full name from email."""
        log.info("Retrieving user full name", extra={"email": email})
        try:
            user = User.objects.get(email=email)
            log.debug(
                "Found user for full name",
                extra={
                    "email": email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                },
            )
            return {
                "first_name": user.first_name,
                "last_name": user.last_name,
            }
        except ObjectDoesNotExist:
            log.info("No user found for full name", extra={"email": email})
            return {"first_name": "", "last_name": ""}

    def get_user_by_social_uid(
        self, uid: str, provider: str = "apple-id"
    ) -> Optional[User]:
        """Get user by social auth UID."""
        log.info(
            "Retrieving user by social UID", extra={"uid": uid, "provider": provider}
        )
        try:
            social_auth = UserSocialAuth.objects.get(provider=provider, uid=uid)
            log.debug(
                "Found user by social UID",
                extra={
                    "uid": uid,
                    "provider": provider,
                    "user_id": social_auth.user.id,
                },
            )
            return social_auth.user
        except ObjectDoesNotExist:
            log.info(
                "No user found for social UID", extra={"uid": uid, "provider": provider}
            )
            return None

    def get_user_details(self, response: Dict[str, Any]) -> Dict[str, str]:
        """Return user details from Apple ID response."""
        log.info("Processing user details from Apple ID response")
        if not response.get("email"):
            log.error("Missing email in Apple ID response")
            raise AuthFailed(self, "Email is required for authentication")

        email = response.get("email", "")
        log.debug("Extracted email from response", extra={"email": email})

        # Get user details from existing user if available
        try:
            user = User.objects.get(email=email)
            log.info("Found existing user", extra={"email": email})
            first_name = user.first_name
            last_name = user.last_name
        except ObjectDoesNotExist:
            log.info("No existing user found", extra={"email": email})
            first_name = ""
            last_name = ""

        username = email.split("@", 1)[0]

        # Fall back to username if name is empty (e.g. new user and Apple
        # didn't send the name in the POST body)
        if not first_name and not last_name:
            first_name = username
            last_name = username

        user_details = {
            "username": username,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
        }
        log.debug("Final user details", extra={"user_details": user_details})
        return user_details

    def get_and_store_state(self, request: Any) -> str:
        """Get and store state for Apple ID authentication."""
        log.info("Getting and storing state")
        state = str(uuid.uuid4())
        session_key = request.session.session_key
        if not session_key:
            request.session.create()
            session_key = request.session.session_key

        cache_key = f"apple_auth_state:{session_key}"
        cache.set(cache_key, state, timeout=300)
        request.session["apple_auth_state"] = state

        log.debug(
            "State stored",
            extra={"state_preview": f"{state[:8]}...", "session_key": session_key},
        )
        return state

    def validate_state(self) -> None:
        """Validate state for Apple ID authentication."""
        log.info("Validating state")
        state = self.strategy.session.get("apple_auth_state")
        if not state:
            log.error("Missing state in session")
            raise AuthStateMissing(self)

        session_key = self.strategy.session.session_key
        cache_key = f"apple_auth_state:{session_key}"
        cached_state = cache.get(cache_key)

        if not cached_state:
            log.error("Missing state in cache")
            raise AuthStateMissing(self)

        if state != cached_state:
            log.error(
                "State mismatch",
                extra={
                    "session_state": f"{state[:8]}...",
                    "cache_state": f"{cached_state[:8]}...",
                },
            )
            raise AuthStateMissing(self)

        log.debug("State validation successful")

    @classmethod
    def verify_patch(cls) -> None:
        """Verify that the patch is applied correctly."""
        log.info("Verifying Apple ID patch")
        try:
            from social_core.backends import apple

            if apple.AppleIdAuth != cls:
                log.error("Apple ID patch verification failed")
                raise RuntimeError("Apple ID patch verification failed")
            log.info("Apple ID patch verified successfully")
        except Exception as e:
            log.error(
                "Apple ID patch verification error",
                extra={"error_type": type(e).__name__, "error_message": str(e)},
            )
            raise

    def request_access_token(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Request access token from Apple ID."""
        log.info("Requesting access token")
        try:
            response = super().request_access_token(*args, **kwargs)
            log.info("Access token request successful")
            return response
        except Exception as e:
            log.error(
                "Access token request failed",
                extra={"error_type": type(e).__name__, "error_message": str(e)},
            )
            raise

    def get_json(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Get JSON response from Apple ID."""
        log.info("Requesting JSON from Apple ID")
        try:
            response = super().get_json(*args, **kwargs)
            log.info("JSON request successful")
            return response
        except Exception as e:
            log.error(
                "JSON request failed",
                extra={"error_type": type(e).__name__, "error_message": str(e)},
            )
            raise


def patch() -> None:
    """Patch the AppleIdAuth class with our implementation."""
    log.info("Starting Apple ID patch application")
    try:
        from social_core.backends import apple

        log.debug("Current AppleIdAuth class", extra={"class": str(apple.AppleIdAuth)})

        apple.AppleIdAuth = IBLAppleIdAuth
        log.info("Successfully patched AppleIdAuth class")

    except Exception as e:
        log.exception("Failed to apply Apple ID patch", extra={"error": str(e)})
        raise
