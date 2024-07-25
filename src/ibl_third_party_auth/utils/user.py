import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from ibl_user_management_api.utils.main import retrieve_user

log = logging.getLogger(__name__)

class UserUtils():
    def __init__(self):
        self.user_model = get_user_model()

    def create_user(self, username, email, first_name=None, last_name=None):
        """
        Create a new user
        """
        user, created = self.user_model.objects.get_or_create(username=username, email=email, first_name=first_name, last_name=last_name)
        if created:
            user = retrieve_user(username)
            if first_name and last_name:
                user.profile.name = f"{first_name}_{last_name}"
            else:
                user.profile.name = username
            user.save()
            return True
        else:
            return False
