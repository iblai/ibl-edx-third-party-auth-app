import logging

from django.contrib import admin
from django.contrib.auth import get_user_model
from django.db.models import signals
from social_django.admin import UserSocialAuthOption
from social_django.models import UserSocialAuth

log = logging.getLogger(__name__)


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


# Override User admin to handle RecursionError during deletion.
# edx-platform models (User <-> UserProfile) have circular __str__ references
# that cause infinite recursion when Django admin's get_deleted_objects() tries
# to build the cascade tree for the delete confirmation page.
User = get_user_model()
_OriginalUserAdmin = type(admin.site._registry.get(User))


class IBLUserAdmin(_OriginalUserAdmin):
    """User admin that handles RecursionError in the delete confirmation page."""

    def get_deleted_objects(self, objs, request):
        try:
            return super().get_deleted_objects(objs, request)
        except RecursionError:
            log.warning(
                "RecursionError in get_deleted_objects for User deletion, "
                "returning simplified object list."
            )
            # Return a simplified result that allows deletion to proceed.
            # get_deleted_objects returns: (deleted_objects, model_count, perms_needed, protected)
            deleted_objects = [str(obj.pk) + " - " + obj.username for obj in objs]
            model_count = {User._meta.verbose_name_plural: len(objs)}
            perms_needed = set()
            protected = []
            return deleted_objects, model_count, perms_needed, protected


if _OriginalUserAdmin is not type(None):
    admin.site.unregister(User)
    admin.site.register(User, IBLUserAdmin)
