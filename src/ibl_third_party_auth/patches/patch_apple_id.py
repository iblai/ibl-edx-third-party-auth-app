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
import redis
from common.djangoapps.third_party_auth import appleid
from common.djangoapps.third_party_auth.appleid import AppleIdAuth
from django.conf import settings
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import PyJWTError
from social_core.exceptions import AuthFailed, AuthStateMissing

log = logging.getLogger(__name__)


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

    def auth_params(self, *args, **kwargs):
        """
        Apple requires to set `response_mode` to `form_post` if `scope`
        parameter is passed.
        """
        params = super().auth_params(*args, **kwargs)
        if self.RESPONSE_MODE:
            params["response_mode"] = self.RESPONSE_MODE
        elif self.get_scope():
            params["response_mode"] = "form_post"
        return params

    def get_private_key(self):
        """
        Return contents of the private key file. Override this method to provide
        secret key from another source if needed.
        """
        return self.setting("SECRET")

    def generate_client_secret(self):
        """
        Generate a client secret for Apple ID authentication.
        """
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

        log.info(
            f"Generating client secret with: client_id={client_id}, team_id={team_id}, key_id={key_id}"
        )

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
            log.error(f"Error generating client secret: {str(e)}")
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

    def get_user_details(self, response):
        name = response.get("name") or {}
        email = response.get("email", "")
        if not email:
            log.error("No email supplied w/ appleid login: %s", response)
        fullname, first_name, last_name = self.get_user_names(
            fullname=str(email).split("@")[0],
            first_name=name.get("firstName", ""),
            last_name=name.get("lastName", ""),
        )
        apple_id = response.get(self.ID_KEY, "")
        # prevent updating User with empty strings
        user_details = {
            "fullname": str(email).split("@")[0],
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
        state = str(uuid.uuid4())  # Generate a unique state
        session_key = request.session.session_key
        if not session_key:
            request.session.create()
            session_key = request.session.session_key

        redis_client = redis.Redis.from_url(settings.REDIS_URL)
        redis_key = f"apple_auth_state:{session_key}"
        redis_client.setex(redis_key, 300, state)  # Store for 5 minutes

        return state

    def validate_state(self):
        state = self.get_request_state()
        session_key = self.strategy.session.session_key

        redis_client = redis.Redis.from_url(settings.REDIS_URL)
        redis_key = f"apple_auth_state:{session_key}"
        stored_state = redis_client.get(redis_key)

        if not stored_state or stored_state.decode() != state:
            raise AuthStateMissing(self, "state")

        # Remove the used state
        redis_client.delete(redis_key)

        return state


def patch():
    appleid.AppleIdAuth = IBLAppleIdAuth
