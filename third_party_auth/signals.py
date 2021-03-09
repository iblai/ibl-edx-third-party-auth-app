import logging
from importlib import import_module

from django.conf import settings
from django.dispatch import receiver

from student.models import UserProfile
from django.contrib.auth.signals import user_logged_in, user_logged_out

SessionStore = import_module(settings.SESSION_ENGINE).SessionStore  # pylint: disable=invalid-name
log = logging.getLogger(__name__)


@receiver(user_logged_in)
@receiver(user_logged_out)
def cms_enforce_single_login(sender, request, user, signal, **kwargs):    # pylint: disable=unused-argument
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
    log.info("Checking ibl cms_enfore_single_login")
    if getattr(settings, 'IBL_CMS_PREVENT_CONCURRENT_LOGINS', False):
        if signal == user_logged_in:
            key = request.session.session_key
        else:
            key = None
        log.info('IBL Enforce single login session key: %s', key)
        if user:
            user_profile, __ = UserProfile.objects.get_or_create(
                user=user,
                defaults={'name': user.username}
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
    old_login = meta.get('cms_session_id', None)
    if old_login:
        SessionStore(session_key=old_login).delete()
        log.info("Deleted old session_id = %s", old_login)
    meta['cms_session_id'] = session_id
    log.info("setting cms_session_id = %s", session_id)
    profile.set_meta(meta)
    profile.save()
