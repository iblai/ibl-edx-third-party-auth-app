"""
User API views
"""
import logging

from common.djangoapps.third_party_auth.appleid import AppleIdAuth
from ibl_user_management_api.utils.main import (
    create_or_update_user,
)
from ibl_user_management_api.utils.request import (
    validate_user_params,
)
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from social_core.backends.base import BaseAuth
from social_core.strategy import BaseStrategy
from social_django.utils import load_strategy

log = logging.getLogger(__name__)

class CustomStrategy(BaseStrategy):
    def __init__(self, request):
        self.request = request

    def get_setting(self, name):
        # Implement this method to return the appropriate setting
        # For example, you can fetch settings from Django settings or environment variables
        from django.conf import settings
        return getattr(settings, name, None)

    def request_data(self, merge=True):
        return self.request.data

    def request_host(self):
        return self.request.get_host()

    def build_absolute_uri(self, path=None):
        return self.request.build_absolute_uri(path)

    def redirect(self, url):
        return Response({'redirect': url}, status=status.HTTP_302_FOUND)

    def html(self, content):
        return Response({'html': content}, status=status.HTTP_200_OK)

    def authenticate(self, backend, *args, **kwargs):
        return None

class IblUserManagementView(APIView, AppleIdAuth):
    """
    User API extension.
    """
    authentication_classes = []
    permission_classes = []

    def create_user_account(self, params):
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

    def post(self, request, *args, **kwargs):
        self.strategy = load_strategy(request)
        id_token = request.data.get('access_token')
        if not id_token:
            return Response({'error': 'Missing id_token parameter'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            decoded_data = self.decode_id_token(id_token)
            return Response({'decoded_data': decoded_data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def some_post(self, request, *args, **kwargs):
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
        # self.strategy = load_strategy(request)
        self.strategy = CustomStrategy(request)
        self.backend = BaseAuth(self.strategy, 'apple-id')
        params = request.data
        log.info("Params: %s", params)

        # Extract new parameters
        backend = params.get("backend")
        access_token = params.get("access_token")

        # Verify access token if backend is provided
        if backend:
            if backend == "apple-id":
                access_token = request.data.get('access_token')
                log.info("Access token: %s", access_token)
                if not access_token:
                    return Response({'error': 'Missing access_token parameter'}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    decoded_data = self.decode_id_token(access_token)
                    log.info("Decoded data: %s", decoded_data)
                    # process apple request
                    self.create_user_account(params)
                    return Response({'decoded_data': decoded_data}, status=status.HTTP_200_OK)
                except Exception as e:
                    return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

            elif backend == "google-oauth2":
                is_valid = self.verify_google_access_token(access_token)
                if is_valid:
                    return "The access_token is valid."
            else:
                return Response({"error": "Unsupported backend."}, status=400)

            if not is_valid:
                return Response({"error": "Invalid access token."}, status=400)



