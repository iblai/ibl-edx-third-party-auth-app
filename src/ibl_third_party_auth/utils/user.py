from django.contrib.auth import get_user_model
from django.contrib.auth.models import User


class UserUtils():
    def __init__(self):
        self.user_model = get_user_model()

    def create_user(self, username, email, first_name=None, last_name=None):
        """
        Create a new user
        """
        user, created = self.user_model.objects.get_or_create(username=username, email=email, first_name=first_name, last_name=last_name)
        if created:
            return True
        else:
            return False
