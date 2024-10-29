import logging
from importlib import import_module

from common.djangoapps.student.models import UserProfile
from django.conf import settings
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.db.models.signals import post_save
from django.dispatch import receiver
from social_django.models import UserSocialAuth

from ibl_third_party_auth.utils.provider_utils import (
    get_monitored_provider,
    get_platform_key_from_provider,
    get_provider_config_by_backend,
)
from ibl_third_party_auth.utils.user_platform_link import link_user_to_platform

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore  # pylint: disable=invalid-name
log = logging.getLogger(__name__)


@receiver(user_logged_in)
@receiver(user_logged_out)
def cms_enforce_single_login(sender, request, user, signal, **kwargs):  # pylint: disable=unused-argument
    """
    Sets the current session id in the user profile,
    to prevent concurrent logins within the CMS only

    If we enable the normal PREVENT_CONCURRENT_LOGINS in the LMS and CMS, then
    we can only login to a _single_ lms OR cms. We need to be able to login
    to a single LMS _and_ a single CMS. So we do the same thing with a different
    meta key.

    This was taken and adapted from:
    https://github.com/edx/edx-platform/blob/open-release/ironwood.master/common/djangoapps/student/models.py#L2260-L2278

    """
    if getattr(settings, "IBL_CMS_PREVENT_CONCURRENT_LOGINS", False):
        if signal == user_logged_in:
            key = request.session.session_key
        else:
            key = None
        if user:
            user_profile, __ = UserProfile.objects.get_or_create(
                user=user, defaults={"name": user.username}
            )
            if user_profile:
                set_cms_login_session(user_profile, key)


def set_cms_login_session(profile, session_id=None):
    """
    Sets the current session id for the logged-in user.
    If session_id doesn't match the existing session,
    deletes the old session object.
    """
    meta = profile.get_meta()
    old_login = meta.get("cms_session_id", None)
    if old_login:
        SessionStore(session_key=old_login).delete()
    meta["cms_session_id"] = session_id
    profile.set_meta(meta)
    profile.save()


@receiver(post_save, sender=UserSocialAuth)
def handle_social_auth_creation(sender, instance, created, **kwargs):
    """
    Signal handler to automatically link users to platforms when their social auth account is created.

    Args:
        sender: The model class (UserSocialAuth)
        instance: The actual UserSocialAuth instance
        created (bool): True if this is a new instance
        **kwargs: Additional keyword arguments
    """
    if not created:
        return

    monitored_provider = get_monitored_provider()

    # Check if this is the provider we want to monitor
    if instance.provider != monitored_provider:
        return

    log.info(
        f"New social auth created for user {instance.user.id} with provider {instance.provider}"
    )

    # Get provider configuration
    provider_config = get_provider_config_by_backend(instance.provider)
    if not provider_config:
        log.error(f"No provider configuration found for {instance.provider}")
        return

    # Get platform key from provider config
    platform_key = get_platform_key_from_provider(provider_config)
    if not platform_key:
        log.error("Could not get platform key from provider configuration")
        return

    # Link user to platform
    try:
        result = link_user_to_platform(instance.user.id, platform_key)
        if result:
            log.info(
                f"Successfully linked user {instance.user.id} to platform {platform_key} "
                f"after social auth creation"
            )
        else:
            log.error(
                f"Failed to link user {instance.user.id} to platform {platform_key} "
                f"after social auth creation"
            )
    except Exception as e:
        log.exception(
            f"Error linking user {instance.user.id} to platform {platform_key} "
            f"after social auth creation: {str(e)}"
        )
