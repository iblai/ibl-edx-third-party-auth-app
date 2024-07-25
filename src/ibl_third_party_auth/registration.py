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


class UserManagementView(APIView):
    """
    User API extension.
    """
    authentication_classes = []
    permission_classes = []

    def get(self, request, format=None):
        """
        Get basic user information.
        Modification of openedx.core.djangoapps.user_api.accounts.views.AccountViewSet.retrieve

        Params:
        username or email or user_id: precedence order [user_id > username > email]
        """
        is_admin_request = (request.user.is_superuser or request.user.is_staff)

        user, error_response = get_user_from_request(request, source=self)
        if not user:
            if is_admin_request:
                return error_response
            else:
                return Response(status=404)

        # Check for admin user if request user doesn't match
        if not is_admin_request and (user != request.user):
            return Response(status=404)

        username = user.username
        try:
            account_settings = get_account_settings(
                request, [username], view=request.query_params.get('view'))
        except UserNotFound:
            return Response(status=403)

        response = account_settings[0]
        if response:
            # Add user ID
            response["id"] = user.id
            response["is_superuser"] = user.is_superuser
            response["is_staff"] = user.is_staff


        return Response(response)


    def post(self, request, format=None):
        """
        Create user with the manage_user command.

        username: Username
        email: User email
        name: Name of user
        password (optional): If unsupplied, an unused password used as placeholder
        provider (optional): Supply the provider to link with.
        is_staff (optional): Defaults to false
        is_active (optional): Defaults to true on create
        update (optional): Update user information
        force_create (TODO)
        """
        # Check for admin user
        if not (request.user.is_superuser or request.user.is_staff):
            return Response(status=404)

        params = request.data

        # Validate request parameters
        validation_response = validate_user_params(params)
        if validation_response:
            return validation_response

        # Create or update user
        user, user_response = create_or_update_user(params)
        return user_response