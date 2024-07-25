import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.models import User

log = logging.getLogger(__name__)

class UserUtils():
    def __init__(self):
        self.user_model = get_user_model()

    def create_user(self, username, email, first_name=None, last_name=None):
        """
        Create a new user
        """
        user, created = self.user_model.objects.get_or_create(username=username, email=email, first_name=first_name, last_name=last_name)
        log.info("User created: %s", user)
        if created:
            # Create user profile
            profile = self.profile_model(user=user)
            if first_name and last_name:
                profile.name = f"{first_name}_{last_name}"
            else:
                profile.name = username
            profile.save()
            user.save()
            return True
        else:
            return False
