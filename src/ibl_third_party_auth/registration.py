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
        import remote_pdb
        remote_pdb.RemotePdb('0.0.0.0', 4444).set_trace()
        id_token = request.data.get('access_token')
        log.info(f"id_token: {id_token}" )
        if not id_token:
            return Response({'error': 'Missing id_token parameter'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            log.info("Decoding id token.........")
            decoded_data = self.decode_id_token(id_token)
            return Response({'decoded_data': decoded_data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

