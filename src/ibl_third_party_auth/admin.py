from django.contrib import admin
from social_django.admin import UserSocialAuthOption
from social_django.models import UserSocialAuth


class IBLUserSocialAuthAdmin(UserSocialAuthOption):
    """
    Custom admin for UserSocialAuth that ensures our signal handler is triggered
    for admin actions.
    """

    def save_model(self, request, obj, form, change):
        # Store the action type in the request object
        request._social_auth_action = "change" if change else "addition"
        super().save_model(request, obj, form, change)


# Unregister the default admin and register our custom one
admin.site.unregister(UserSocialAuth)
admin.site.register(UserSocialAuth, IBLUserSocialAuthAdmin)
