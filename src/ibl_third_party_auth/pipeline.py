"""
Custom pipeline steps for social auth.

This module provides pipeline steps that run before edx-platform's
ensure_user_information to auto-create users during SSO login,
preventing unwanted redirects to the registration page.
"""

import logging

from django.conf import settings
from django.contrib.auth import get_user_model

log = logging.getLogger(__name__)
User = get_user_model()


def auto_create_user(strategy, details, user=None, *args, **kwargs):
    """
    Auto-create a Django user (and UserProfile) for new SSO users.

    Must run before ensure_user_information so that the user object exists
    when that step checks whether to redirect to the registration form.

    Returns None to continue the pipeline, or a dict with the new user.
    """
    if user is not None:
        return None

    if getattr(settings, "SOCIAL_AUTH_DISABLE_USER_CREATION", False):
        return None

    email = details.get("email")
    username = strategy.storage.user.get_username(details)
    if not email or not username:
        return None

    # If a user with this email already exists, return them
    existing = User.objects.filter(email=email).first()
    if existing:
        log.info("auto_create_user: found existing user by email %s", email)
        return {"user": existing, "is_new": False}

    # Create the user
    user = User.objects.create_user(username=username, email=email)
    user.is_active = True
    user.save(update_fields=["is_active"])

    # Create a UserProfile (required by edx-platform)
    try:
        from common.djangoapps.student.models import UserProfile

        fullname = details.get("fullname") or username
        UserProfile.objects.get_or_create(user=user, defaults={"name": fullname})
    except Exception:
        log.exception("auto_create_user: failed to create UserProfile for %s", username)

    log.info("auto_create_user: created user %s (%s)", username, email)
    return {"user": user, "is_new": True}
