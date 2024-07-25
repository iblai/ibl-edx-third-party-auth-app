"""
User API views
"""
import logging
import time

import requests
from common.djangoapps.third_party_auth.appleid import AppleIdAuth
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
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView
from social_core.backends.oauth import BaseOAuth2
from social_django.utils import load_backend, load_strategy

from ibl_third_party_auth.patches.patch_apple_id import IBLAppleIdAuth

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

    def get_apple_jwk(self, kid):
        response = requests.get(self.JWK_URL)
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
            if not public_key.verify(message.encode('utf-8'), decoded_signature):
                return False

            # Decode and validate the claims
            claims = jwt.get_unverified_claims(access_token)
            log.info(f"Claims: {claims}")

            # Example claim validation (you can add more as needed)
            if claims['aud'] != settings.CLIENT:
                return False
            if claims['exp'] < time.time():
                return False

            return claims
        except Exception as e:
            print(f"Token verification failed: {e}")
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
        log.info("User registration request.........")
        # import remote_pdb
        # remote_pdb.RemotePdb('0.0.0.0', 4444).set_trace()
        id_token = request.data.get('access_token')
        log.info(f"id_token: {id_token}" )
        if not id_token:
            return Response({'error': 'Missing id_token parameter'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            log.info("Decoding id token.........")
            decoded_data = self.verify_apple_access_token(id_token)
            return Response({'decoded_data': decoded_data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def create_user_account(self, request):
        params = request.data
        log.info("Params: %s", params)

        import re

        # Extract new parameters

        client_id = params.get("client_id")
        asymmetric_jwt = params.get("asymmetric_jwt")
        token_type = params.get("token_type")
        access_token = params.get("access_token")
        scope = params.get("scope")
        email = params.get("email")
        first_name = params.get("first_name")
        last_name = params.get("last_name")

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
