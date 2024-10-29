from django.contrib import admin
from django.db.models import signals
from social_django.admin import UserSocialAuthOption
from social_django.models import UserSocialAuth


class IBLUserSocialAuthAdmin(UserSocialAuthOption):
    """
    Custom admin for UserSocialAuth that ensures our signal handler is triggered
    for admin actions.
    """

    def save_model(self, request, obj, form, change):
        """
        Given a model instance save it to the database.
        """
        # Store the action type in the request object
        request._social_auth_action = "change" if change else "addition"

        # Get the original instance if this is an update
        if change:
            original = UserSocialAuth.objects.get(pk=obj.pk)
        else:
            original = None

        # Save the model
        obj.save()

        # Explicitly send the signal
        if not change:
            signals.post_save.send(
                sender=UserSocialAuth,
                instance=obj,
                created=True,
                raw=False,
                using=None,
                update_fields=None,
                request=request,
            )
        else:
            signals.post_save.send(
                sender=UserSocialAuth,
                instance=obj,
                created=False,
                raw=False,
                using=None,
                update_fields=None,
                request=request,
            )


# Unregister the default admin and register our custom one
admin.site.unregister(UserSocialAuth)
admin.site.register(UserSocialAuth, IBLUserSocialAuthAdmin)
