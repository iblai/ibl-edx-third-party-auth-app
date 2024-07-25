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

log = logging.getLogger(__name__)


class IblUserManagementView(APIView, AppleIdAuth):
    """
    User API extension.
    """
    authentication_classes = []
    permission_classes = []

    # def create_user_account(self, request):
    #     params = request.data
    #     log.info("Params: %s", params)

    #     import re

    #     # Extract new parameters

    #     client_id = params.get("client_id")
    #     asymmetric_jwt = params.get("asymmetric_jwt")
    #     token_type = params.get("token_type")
    #     access_token = params.get("access_token")
    #     scope = params.get("scope")
    #     email = params.get("email")
    #     first_name = params.get("first_name")
    #     last_name = params.get("last_name")

    #     # Generate name and username
    #     if first_name and last_name:
    #         name = f"{first_name} {last_name}"
    #     elif email:
    #         local_part = email.split('@')[0]
    #         domain_part = email.split('@')[1].replace('.', '_')
    #         local_part = re.sub(r'\W+', '_', local_part)  # Replace all non-alphanumeric characters with underscores
    #         name = local_part.replace('_', ' ')
    #         username = f"{local_part}_{domain_part}"
    #     else:
    #         return Response({"error": "Email is required if first name and last name are not provided."}, status=400)

    #     # Update params with generated name and username
    #     params["name"] = name
    #     params["username"] = username

    #     log.info("Updated params: %s", params)

    #     # Validate request parameters
    #     validation_response = validate_user_params(params)
    #     if validation_response:
    #         return validation_response

    #     # Create or update user
    #     user, user_response = create_or_update_user(params)
    #     return user_response

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
        
        self.strategy = load_strategy(request)
        access_token = request.data.get('access_token')
        backend = request.data.get("backend")
        if not access_token:
            return Response({'error': 'Missing access_token parameter'}, status=status.HTTP_400_BAD_REQUEST)

        if backend:
            if backend == "apple-id":
                try:
                    decoded_data = self.decode_id_token(access_token)
                except Exception as e:
                    decoded_data = None
                    return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

                if decoded_data is None:
                    return Response({"error": "Invalid access token."}, status=400)

            elif backend == "google-oauth2":
                is_valid = self.verify_google_access_token(access_token)
                if is_valid:
                    return "The access_token is valid."
            else:
                return Response({"error": "Unsupported backend."}, status=400)







