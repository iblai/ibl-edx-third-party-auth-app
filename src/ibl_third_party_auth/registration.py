"""
User API views
"""

import logging
import time

import requests
from jose import jwk, jwt
from jose.utils import base64url_decode
from jwt.algorithms import RSAAlgorithm
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from social_django.utils import load_strategy

from ibl_third_party_auth.patches.patch_apple_id import IBLAppleIdAuth
from ibl_third_party_auth.utils.provider_utils import IBLProviderConfig
from ibl_third_party_auth.utils.user import UserUtils

log = logging.getLogger(__name__)


class IblUserManagementView(APIView, IBLAppleIdAuth):
    """
    User API extension.
    """

    authentication_classes = []
    permission_classes = []
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

    GOOGLE_JWK_URL = "https://www.googleapis.com/oauth2/v3/certs"

    def get_google_jwk(self, kid):
        response = requests.get(self.GOOGLE_JWK_URL)
        response.raise_for_status()
        keys = response.json().get("keys")

        for key in keys:
            if key["kid"] == kid:
                return key
        raise ValueError("Key ID not found in Google's JWKs")

    def verify_google_jwt_token(self, id_token, access_token, backend="google-oauth2"):
        try:
            # Decode the JWT header to get the Key ID (kid)
            header = jwt.get_unverified_header(id_token)
            kid = header["kid"]

            # Get the public key from Google's JWKs
            jwk_key = self.get_google_jwk(kid)
            public_key = RSAAlgorithm.from_jwk(jwk_key)

            try:
                claims = jwt.decode(
                    token=id_token,
                    key=public_key,
                    access_token=access_token,
                    algorithms=["RS256"],
                    issuer="https://accounts.google.com",
                    options={"verify_sub": False, "verify_jti": False, "verify_at_hash": False, "verify_aud": False},
                )
            except Exception as e:
                log.error(f"Error decoding token: {e}")
                return False

            # Check the expiration
            if claims["exp"] < time.time():
                log.error("Error: Token has expired")
                return False

            # Verify the JWT signature and decode the token
            provider = IBLProviderConfig()
            audience = provider.get_audience(backend)

            if claims["aud"] not in audience:
                log.error(f"Error: Provided audience: {claims['aud']} is not in the list of valid audiences: {audience}")
                return False

            return claims
        except Exception as e:
            log.error(f"Token verification failed: {e}")
            return False

    def get_apple_jwk(self, kid):
        response = requests.get(self.JWK_URL)
        response.raise_for_status()
        keys = response.json().get("keys")

        for key in keys:
            if key["kid"] == kid:
                return key
        raise ValueError("Key ID not found in Apple's JWKs")

    def verify_apple_access_token(self, access_token):
        try:
            # Decode the JWT header to get the Key ID (kid)
            header = jwt.get_unverified_header(access_token)
            kid = header["kid"]

            # Get the public key from Apple's JWKs
            jwk_key = self.get_apple_jwk(kid)
            public_key = jwk.construct(jwk_key)

            # Verify the JWT signature
            message, encoded_signature = access_token.rsplit(".", 1)
            decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
            if not public_key.verify(message.encode("utf-8"), decoded_signature):
                log.error("Error: Signature verification failed")
                return False

            claims = jwt.get_unverified_claims(access_token)
            if isinstance(self.setting("AUDIENCE"), list):
                if claims["aud"] not in self.setting("AUDIENCE"):
                    log.error(f"Error: Provided audience: {claims['aud']} is not in the list of valid audiences: {self.setting('AUDIENCE')}")
                    return False
            else:
                if claims["aud"] != self.setting("AUDIENCE"):
                    log.error(f"Error: Provided audience: {claims['aud']} is not the valid audience: {self.setting('AUDIENCE')}")
                    return False
            if claims["exp"] < time.time():
                log.error("Error: Token has expired")
                return False

            return True
        except Exception as e:
            log.error(f"Token verification failed: {e}")
            return False

    def post(self, request, format=None):
        """
        Create user with the manage_user command.

        client_id: Client ID
        asymmetric_jwt: Asymmetric JWT
        token_type: Token type
        access_token: Access token
        scope: Scope
        email: User email
        first_name (optional): First name of user
        last_name (optional): Last name of user
        """
        self.strategy = load_strategy(request)
        backend = request.data.get("backend")

        if backend == "apple-id":
            id_token = request.data.get("access_token")
            if not id_token:
                return Response(
                    {"error": "Missing id_token parameter"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            try:
                decoded_data = self.verify_apple_access_token(id_token)
                if not decoded_data:
                    return Response(
                        {"error": "access_token could not be verified"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                create_user = self.create_user_account(request)
                if create_user:
                    return Response(
                        {"message": "Account created successfully"},
                        status=status.HTTP_200_OK,
                    )
                else:
                    return Response(
                        {"error": "Account could not be created"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except Exception as e:
                log.error("Error creating user: %s", e)
                return Response(
                    {"error": "Account could not be created"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif backend == "google-oauth2":
            id_token = request.data.get("id_token")
            access_token = request.data.get("access_token")
            if not id_token:
                return Response(
                    {"error": "Missing id_token parameter"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            try:
                decoded_data = self.verify_google_jwt_token(id_token, access_token, backend)
                if not decoded_data:
                    return Response(
                        {"error": "id_token could not be verified"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                create_user = self.create_user_account(request, decoded_data, backend)

                if create_user:
                    return Response(
                        {"message": "Account created successfully"},
                        status=status.HTTP_200_OK,
                    )
                else:
                    return Response(
                        {"error": "Account could not be created"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except Exception as e:
                log.error("Error creating user: %s", e)
                return Response(
                    {"error": "Account could not be created"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {"error": "Invalid backend"}, status=status.HTTP_400_BAD_REQUEST
            )

    def create_user_account(self, request, data={}, backend="apple-id"):
        import re
        if backend == "apple-id":
            params = request.data
            email = params.get("email")
            first_name = params.get("first_name")
            last_name = params.get("last_name")

            if email:
                local_part = email.split("@")[0]
                domain_part = email.split("@")[1].replace(".", "_")
                local_part = re.sub(r"\W+", "_", local_part)
                username = f"{local_part}_{domain_part}"
                if not first_name:
                    first_name = local_part
                if not last_name:
                    last_name = local_part
            else:
                log.error("Error: Email not found in request")
                return False
        elif backend == "google-oauth2":
            email = data.get("email")
            first_name = data.get("given_name")
            last_name = data.get("family_name")

            if email:
                local_part = email.split("@")[0]
                domain_part = email.split("@")[1].replace(".", "_")
                local_part = re.sub(r"\W+", "_", local_part)
                username = f"{local_part}_{domain_part}"

                if not first_name:
                    first_name = local_part
                if not last_name:
                    last_name = local_part
            else:
                log.error("Error: Email not found in token")
                return False
        else:
            log.error("Error: Invalid backend")
            return False

        user_utils = UserUtils()
        user_response = user_utils.create_user(username, email, first_name, last_name)

        return user_response
