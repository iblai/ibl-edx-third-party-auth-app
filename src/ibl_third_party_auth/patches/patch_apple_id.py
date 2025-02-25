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


def verify_redis_cache():
    """Verify that Django's cache backend is Redis."""
    from django.conf import settings

    cache_backend = settings.CACHES.get("default", {}).get("BACKEND", "")
    if cache_backend == "django_redis.cache.RedisCache":
        log.info("Using Redis cache backend")
        return True
    else:
        log.warning(f"Cache backend is not Redis (found: {cache_backend})")
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

    def __init__(self, *args, **kwargs):
        log.info("Starting Apple ID authentication flow")
        super().__init__(*args, **kwargs)
        # Verify Redis cache on initialization
        verify_redis_cache()

    def auth_complete(self, *args, **kwargs):
        """Complete the auth process."""
        log.info("IBLAppleIdAuth.auth_complete called")
        try:
            log.debug(f"Auth complete args: {args}")
            log.debug(f"Auth complete kwargs: {kwargs}")

            response = super().auth_complete(*args, **kwargs)
            log.info("Auth complete process successful")
            return response
        except Exception as e:
            log.error(f"Auth complete process failed: {str(e)}")
            if hasattr(e, "response"):
                log.error(f"Response status: {e.response.status_code}")
                log.error(f"Response content: {e.response.content}")
            raise

    def auth_params(self, state=None, *args, **kwargs):
        """
        Apple requires to set `response_mode` to `form_post` if `scope`
        parameter is passed.
        """
        log.info("Generating auth params")
        params = super().auth_params(state=state, *args, **kwargs)

        if self.RESPONSE_MODE:
            params["response_mode"] = self.RESPONSE_MODE
        elif self.get_scope():
            params["response_mode"] = "form_post"

        # Store state in both cache and session
        if state:
            # Only show first 8 chars of state
            state_preview = f"{state[:8]}..." if state else None
            log.info(f"Storing state in auth_params: {state_preview}")
            try:
                session_key = self.strategy.session.session_key
                if not session_key:
                    self.strategy.session.create()
                    session_key = self.strategy.session.session_key

                cache_key = f"apple_auth_state:{session_key}"
                cache.set(cache_key, state, timeout=300)
                self.strategy.session["apple_auth_state"] = state

                # Verify storage (using masked state value)
                stored_cache_state = cache.get(cache_key)
                stored_session_state = self.strategy.session.get("apple_auth_state")
                log.info(f"State stored in cache: {state_preview}")
                log.info(f"State stored in session: {state_preview}")
            except Exception as e:
                log.error(
                    f"Error storing state in auth_params: {str(e)}", exc_info=True
                )

        log.debug(f"Auth params: {params}")
        return params

    def get_private_key(self):
        """
        Return contents of the private key file. Override this method to provide
        secret key from another source if needed.
        """
        return self.setting("SECRET")

    def generate_client_secret(self):
        """Generate a client secret for Apple ID authentication."""
        now = int(time.time())
        client_id = self.setting("CLIENT")
        team_id = self.setting("TEAM")
        key_id = (
            settings.SOCIAL_AUTH_APPLE_ID_KEY
            if hasattr(settings, "SOCIAL_AUTH_APPLE_ID_KEY")
            else ""
        )
        private_key = self.get_private_key()

        log.info("Generating client secret for Apple ID authentication")
        # Removed logging of sensitive data (client_id, team_id, key_id)

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
            log.error("Failed to generate client secret")
            raise

    def get_apple_jwk(self, kid=None):
        """
        Return requested Apple public key or all available.
        """
        keys = self.get_json(url=self.JWK_URL).get("keys")

        if not isinstance(keys, list) or not keys:
            raise AuthFailed(self, "Invalid jwk response")

        if kid:
            return json.dumps([key for key in keys if key["kid"] == kid][0])
        else:
            return (json.dumps(key) for key in keys)

    def decode_id_token(self, id_token):
        """
        Decode and validate JWT token from apple and return payload including
        user data.
        """
        if not id_token:
            raise AuthFailed(self, "Missing id_token parameter")

        try:
            kid = jwt.get_unverified_header(id_token).get("kid")
            log.info(f"Decoding id_token with kid: {kid}")
            public_key = RSAAlgorithm.from_jwk(self.get_apple_jwk(kid))
            decoded = jwt.decode(
                id_token,
                key=public_key,
                audience=self.get_audience(),
                algorithms=["RS256"],
            )
            log.info("id_token decoded successfully")
            return decoded
        except PyJWTError as e:
            log.error(f"Token validation failed: {str(e)}")
            raise AuthFailed(self, "Token validation failed")

    def get_user_fullname(self, email):
        log.info(f"Checking user detail for email: {email}")
        try:
            # Check if the user exists
            user = User.objects.get(email=email)
            # If exists, return first name and last name
            log.info(
                f"User detail found for email: {email}, using: {user.first_name} {user.last_name}"
            )
            return user.first_name, user.last_name
        except ObjectDoesNotExist:
            # User does not exist
            log.info(f"No user detail found for email: {email}")
            return "", ""

    def get_user_by_social_uid(self, uid, provider="apple-id"):
        """
        Fetch the Open edX user associated with a given social auth UID.

        Args:
            provider (str): The name of the social authentication provider (e.g., 'apple', 'google-oauth2').
            uid (str): The UID provided by the social auth provider.

        Returns:
            dict: A dictionary with user details if found, otherwise None.
        """
        log.info(f"Checking user detail for apple_id: {uid}")
        try:
            # Get the social auth entry
            social_auth = UserSocialAuth.objects.get(provider=provider, uid=uid)

            # Retrieve the associated user
            user = social_auth.user

            # Prepare user details to return
            return user.first_name, user.last_name

        except UserSocialAuth.DoesNotExist:
            log.info(f"No user detail found for apple_id: {uid}")
            return "", ""

    def get_user_details(self, response):
        """Get user details from the response."""
        name = response.get("name") or {}
        email = response.get("email", "")
        if not email:
            log.error("No email provided in Apple ID response")

        # Log successful user detail retrieval without exposing data
        log.info("Retrieved user details from Apple ID response")
        if email:
            log.info("Email address present in response")
        apple_id = response.get(self.ID_KEY, "")

        # Check if user creation is disabled and if the user exists
        if getattr(settings, "SOCIAL_AUTH_DISABLE_USER_CREATION", False):
            # Check if user exists by email
            user_exists = User.objects.filter(email=email).exists() if email else False
            # Check if user exists by username (using email or apple_id based on settings)
            username = email if self.setting("EMAIL_AS_USERNAME") else apple_id
            username_exists = (
                User.objects.filter(username=username).exists() if username else False
            )
            # Check if user exists by social auth
            social_auth_exists = (
                UserSocialAuth.objects.filter(provider=self.name, uid=apple_id).exists()
                if apple_id
                else False
            )

            if not user_exists and not username_exists and not social_auth_exists:
                log.error(
                    f"User creation disabled and no existing user found for Apple ID login. "
                    f"Checked email, username and social auth."
                )
                raise PermissionDenied(
                    "User creation is disabled. Please contact support if you need access."
                )

            log.info("Found existing user match for Apple ID login")

        # Add call to check if user detail exists
        log.info(f"Checking user detail for email: {email}")
        get_first_name, get_last_name = self.get_user_fullname(email)

        if not get_first_name and not get_last_name:
            log.info(
                f"No user detail found for email: {email}, checking by apple_id: {apple_id}"
            )
            get_first_name, get_last_name = self.get_user_by_social_uid(apple_id)

        get_fullname = ""
        if get_first_name or get_last_name:
            log.info(
                f"User detail found for email: {email}, using: {get_first_name} {get_last_name}"
            )
            get_fullname = f"{get_first_name} {get_last_name}".strip()

        # Rest of the method remains the same
        fullname, first_name, last_name = self.get_user_names(
            fullname=get_fullname or str(email).split("@")[0],
            first_name=name.get("firstName", get_first_name),
            last_name=name.get("lastName", get_last_name),
        )

        user_details = {
            "fullname": fullname or str(email).split("@")[0],
            "first_name": first_name or str(email).split("@")[0],
            "last_name": last_name or str(email).split("@")[0],
            "email": email,
        }
        if email and self.setting("EMAIL_AS_USERNAME"):
            user_details["username"] = email
        if apple_id and not self.setting("EMAIL_AS_USERNAME"):
            user_details["username"] = apple_id

        return user_details

    def get_and_store_state(self, request):
        """Generate and store state parameter."""
        log.info("Generating and storing state parameter")

        state = str(uuid.uuid4())
        session_key = request.session.session_key
        if not session_key:
            request.session.create()
            session_key = request.session.session_key

        log.info(f"Generated state: {state}")

        try:
            if not verify_redis_cache():
                log.warning("Falling back to session-only storage")
                request.session["apple_auth_state"] = state
                return state

            # Store state using Django's cache framework
            cache_key = f"apple_auth_state:{session_key}"
            cache.set(cache_key, state, timeout=300)  # 5 minutes timeout

            # Also store in session for redundancy
            request.session["apple_auth_state"] = state

            # Verify storage
            stored_cache_state = cache.get(cache_key)
            stored_session_state = request.session.get("apple_auth_state")

            log.info(f"State stored in cache: {stored_cache_state}")
            log.info(f"State stored in session: {stored_session_state}")

            return state

        except Exception as e:
            log.error(f"Error storing state: {str(e)}", exc_info=True)
            # Fallback to session-only storage
            request.session["apple_auth_state"] = state
            return state

    def validate_state(self):
        """Validate the state parameter."""
        try:
            log.info("Validating state")
            received_state = self.get_request_state()
            session_key = self.strategy.session.session_key

            # Only log partial state for debugging
            state_preview = received_state[:8] if received_state else None
            log.info(f"Validating state starting with: {state_preview}...")

            # Check if we're using Redis cache
            using_redis = verify_redis_cache()

            if using_redis:
                # Try getting state from cache
                cache_key = f"apple_auth_state:{session_key}"
                stored_cache_state = cache.get(cache_key)
                if stored_cache_state and stored_cache_state == received_state:
                    log.info("State validated from cache")
                    cache.delete(cache_key)
                    return received_state

            # Try session storage
            stored_session_state = self.strategy.session.get("apple_auth_state")
            if stored_session_state and stored_session_state == received_state:
                log.info("State validated from session")
                del self.strategy.session["apple_auth_state"]
                return received_state

            if not using_redis and not stored_session_state:
                log.warning("No stored state found (session only)")
            elif using_redis and not stored_cache_state and not stored_session_state:
                log.warning("No stored state found (cache and session)")

            if (
                hasattr(settings, "SOCIAL_AUTH_APPLE_ID_SKIP_STATE_VALIDATION")
                and settings.SOCIAL_AUTH_APPLE_ID_SKIP_STATE_VALIDATION
            ):
                log.warning("State validation bypassed per settings")
                return received_state

            log.info("State validated successfully")
            return received_state

        except Exception as e:
            log.error("State validation failed")
            raise

    @classmethod
    def verify_patch(cls):
        """Verify that this class is being used as the AppleIdAuth."""
        from common.djangoapps.third_party_auth import appleid

        current_class = appleid.AppleIdAuth
        log.info(f"Current AppleIdAuth class: {current_class}")
        return current_class == cls

    def request_access_token(self, *args, **kwargs):
        """Request the access token from Apple."""
        try:
            log.info("Requesting access token from Apple")
            response = super().request_access_token(*args, **kwargs)
            log.info("Access token received successfully")
            return response
        except Exception as e:
            log.error("Failed to get access token")
            raise

    def get_json(self, *args, **kwargs):
        """Override get_json to add logging."""
        try:
            log.info(
                f"IBLAppleIdAuth.get_json called with url: {kwargs.get('url', args[0] if args else 'No URL')}"
            )
            log.debug(f"get_json args: {args}")
            log.debug(f"get_json kwargs: {kwargs}")
            return super().get_json(*args, **kwargs)
        except Exception as e:
            log.error(f"get_json failed: {str(e)}")
            raise


def patch():
    """Patch the AppleIdAuth class with our implementation."""
    log.info("Applying IBLAppleIdAuth patch...")
    try:
        # Patch all possible import locations
        from common.djangoapps.third_party_auth import appleid
        from social_core.backends import apple

        log.info(f"Current AppleIdAuth class: {appleid.AppleIdAuth}")
        log.info(f"Current social_core AppleIdAuth class: {apple.AppleIdAuth}")

        # Patch both locations
        appleid.AppleIdAuth = IBLAppleIdAuth
        apple.AppleIdAuth = IBLAppleIdAuth

        # Verify patches
        log.info(f"After patching appleid.AppleIdAuth: {appleid.AppleIdAuth}")
        log.info(f"After patching apple.AppleIdAuth: {apple.AppleIdAuth}")

        # Add a hook to the request_access_token method to ensure our patch is used
        from social_core.backends.oauth import BaseOAuth2

        original_request_access_token = BaseOAuth2.request_access_token

        def patched_request_access_token(self, *args, **kwargs):
            log.info(f"request_access_token called on {self.__class__}")
            if isinstance(self, IBLAppleIdAuth):
                log.info("Using IBLAppleIdAuth implementation")
            return original_request_access_token(self, *args, **kwargs)

        BaseOAuth2.request_access_token = patched_request_access_token

    except Exception as e:
        log.error(f"Error during patching: {str(e)}", exc_info=True)
        raise
