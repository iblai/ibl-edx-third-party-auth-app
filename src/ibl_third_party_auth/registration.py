"""
User API views
"""
import logging

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

    # def get(self, request, format=None):
    #     """
    #     Get basic user information.
    #     Modification of openedx.core.djangoapps.user_api.accounts.views.AccountViewSet.retrieve

    #     Params:
    #     username or email or user_id: precedence order [user_id > username > email]
    #     """
    #     is_admin_request = (request.user.is_superuser or request.user.is_staff)

    #     user, error_response = get_user_from_request(request, source=self)
    #     if not user:
    #         if is_admin_request:
    #             return error_response
    #         else:
    #             return Response(status=404)

    #     # Check for admin user if request user doesn't match
    #     if not is_admin_request and (user != request.user):
    #         return Response(status=404)

    #     username = user.username
    #     try:
    #         account_settings = get_account_settings(
    #             request, [username], view=request.query_params.get('view'))
    #     except UserNotFound:
    #         return Response(status=403)

    #     response = account_settings[0]
    #     if response:
    #         # Add user ID
    #         response["id"] = user.id
    #         response["is_superuser"] = user.is_superuser
    #         response["is_staff"] = user.is_staff


    #     return Response(response)


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