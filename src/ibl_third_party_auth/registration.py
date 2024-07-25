"""
User API views
"""
import logging
import time

import requests
from django.conf import settings
from django.contrib.auth.models import User
from django.db.models import Q
from ibl_user_management_api.utils.main import (
    create_or_update_user,
    retrieve_user,
    retrieve_user_from_email,
    retrieve_user_from_id,
)
from ibl_user_management_api.utils.request import (
    get_user_from_request,
    validate_user_params,
)
from jose import jwk, jwt
from jose.utils import base64url_decode
from openedx.core.djangoapps.user_api.accounts.api import get_account_settings
from openedx.core.djangoapps.user_api.errors import UserNotFound
from openedx.core.lib.api.view_utils import view_auth_classes
from rest_framework.decorators import api_view
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView

log = logging.getLogger(__name__)


class IblUserManagementView(APIView):
    """
    User API extension.
    """
    authentication_classes = []
    permission_classes = []

    APLLE_JWK_URL = "https://appleid.apple.com/auth/keys"
    GOOGLE_JWK_URL = "https://www.googleapis.com/oauth2/v3/certs"

    def get_apple_jwk(self, kid):
        response = requests.get(self.APLLE_JWK_URL)
        response.raise_for_status()
        keys = response.json().get('keys')

        for key in keys:
            if key['kid'] == kid:
                return key
        raise ValueError("Key ID not found in Apple's JWKs")

    def verify_apple_access_token(self, access_token):
        try:
            # Decode the JWT header to get the Key ID (kid)
            header = jwt.get_unverified_header(access_token)
            log.info(f"Header: {header}")
            kid = header['kid']
            log.info(f"Key ID: {kid}")

            # Get the public key from Apple's JWKs
            jwk_key = self.get_apple_jwk(kid)
            log.info(f"JWK: {jwk_key}")
            public_key = jwk.construct(jwk_key)
            log.info(f"Public key: {public_key}")

            # Verify the JWT signature
            message, encoded_signature = access_token.rsplit('.', 1)
            log.info(f"Message: {message}")
            decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
            log.info(f"Decoded signature: {decoded_signature}")

            if not public_key.verify(message.encode('utf-8'), decoded_signature):
                return False

            # Decode and validate the claims
            claims = jwt.get_unverified_claims(access_token)
            log.info(f"Claims: {claims}")

            # Example claim validation (you can add more as needed)
            if claims['aud'] != self.setting("CLIENT"):
                return False
            if claims['exp'] < time.time():
                return False

            return True
        except Exception as e:
            print(f"Token verification failed: {e}")
            return False

    GOOGLE_JWK_URL = "https://www.googleapis.com/oauth2/v3/certs"

    def get_google_jwk(self, kid):
        log.info("Fetching Google JWKs")
        response = requests.get(self.GOOGLE_JWK_URL)
        response.raise_for_status()
        keys = response.json().get('keys')
        log.info(f"Found {len(keys)} keys in Google's JWKs")

        for key in keys:
            if key['kid'] == kid:
                log.info(f"Found matching key for kid: {kid}")
                return key
        log.error(f"Key ID {kid} not found in Google's JWKs.....")
        raise ValueError("Key ID not found in Google's JWKs.....")

    def verify_google_access_token(self, access_token):
        try:
            log.info("Decoding JWT header")
            header = jwt.get_unverified_header(access_token)
            kid = header['kid']
            log.info(f"Extracted kid from header: {kid} ")

            log.info("Getting public key from Google's JWKs........")
            jwk_key = self.get_google_jwk(kid)
            public_key = jwk.construct(jwk_key)

            log.info("Verifying JWT signature......")
            message, encoded_signature = access_token.rsplit('.', 1)
            decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

            if not public_key.verify(message.encode('utf-8'), decoded_signature):
                log.error("Signature verification failed........")
                return False

            log.info("Decoding and validating claims.........")
            claims = jwt.get_unverified_claims(access_token)

            # Example claim validation (you can add more as needed)
            if claims['aud'] != 'your_client_id':
                log.error("Invalid audience in claims")
                return False
            if claims['exp'] < time.time():
                log.error("Token has expired")
                return False

            log.info("Token is valid")
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
        log.info("User registration request.........")

        params = request.data
        log.info("Params: %s", params)

        import re

        # Extract new parameters
        backend = params.get("backend")
        client_id = params.get("client_id")
        asymmetric_jwt = params.get("asymmetric_jwt")
        token_type = params.get("token_type")
        access_token = params.get("access_token")
        scope = params.get("scope")
        email = params.get("email")
        first_name = params.get("first_name")
        last_name = params.get("last_name")

        # Verify access token if backend is provided
        if backend:
            if backend == "apple-id":
                is_valid = self.verify_apple_access_token(access_token)
                if is_valid:
                    return "The access_token is valid."
            elif backend == "google-oauth2":
                is_valid = self.verify_google_access_token(access_token)
                if is_valid:
                    return "The access_token is valid."
            else:
                return Response({"error": "Unsupported backend."}, status=400)

            if not is_valid:
                return Response({"error": "Invalid access token."}, status=400)

        # Generate name and username
        if first_name and last_name:
            name = f"{first_name} {last_name}"
        elif email:
            local_part = email.split('@')[0]
            domain_part = email.split('@')[1].replace('.', '_')
            local_part = re.sub(r'\W+', '_', local_part)  # Replace all non-alphanumeric characters with underscores
            name = local_part.replace('_', ' ')
            username = f"{local_part}_{domain_part}"
        else:
            return Response({"error": "Email is required if first name and last name are not provided."}, status=400)

        # Update params with generated name and username
        params["name"] = name
        params["username"] = username

        log.info("Updated params: %s", params)

        # Validate request parameters
        validation_response = validate_user_params(params)
        if validation_response:
            return validation_response

        # Create or update user
        user, user_response = create_or_update_user(params)
        return user_response

