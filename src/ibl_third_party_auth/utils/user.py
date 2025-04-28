import logging

from common.djangoapps.student.models import UserProfile
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from ibl_user_management_api.utils.main import retrieve_user

log = logging.getLogger(__name__)


class UserUtils:
    def __init__(self):
        self.user_model = get_user_model()

    def create_user(self, username, email, first_name=None, last_name=None):
        """
        Create a new user if allowed by settings.

        Args:
            username (str): The username for the new user
            email (str): The email address for the new user
            first_name (str, optional): The user's first name
            last_name (str, optional): The user's last name

        Returns:
            bool: True if user was created, False if user already exists

        Raises:
            PermissionDenied: If user creation is disabled and user doesn't exist
        """
        user, created = self.user_model.objects.get_or_create(
            username=username, email=email, first_name=first_name, last_name=last_name
        )
        if created:
            user = retrieve_user(username)
            if first_name and last_name:
                name = first_name + " " + last_name
                profile = UserProfile(user=user, name=name)
            else:
                profile = UserProfile(user=user, name=username)
            profile.save()
            log.info(f"Successfully created new user with username {username}")
            return True
        else:
            log.error(f"Failed to create user with username {username}")
            return False
