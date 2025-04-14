"""
Vendored from social-core:
https://github.com/python-social-auth/social-core/blob/master/social_core/backends/google.py

Additional changes:
- Added support for SOCIAL_AUTH_DISABLE_USER_CREATION setting
- Added enhanced logging
- Added user existence checks before creation
"""

import logging

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from social_core.backends.google import GoogleOAuth2
from social_django.models import UserSocialAuth

log = logging.getLogger(__name__)


class IBLGoogleOAuth2(GoogleOAuth2):
    """
    Google OAuth2 authentication backend with additional features:
    - Respects SOCIAL_AUTH_DISABLE_USER_CREATION setting
    - Enhanced logging
    - User existence checks
    """

    def get_user_details(self, response):
        """Return user details from Google API account."""
        log.info("Getting user details from Google response")

        if not response.get("email"):
            log.error("No email provided in Google response")

        # Get basic details from response
        email = response.get("email", "")

        # Check if user creation is disabled and if the user exists - do this BEFORE processing other details
        if getattr(settings, "SOCIAL_AUTH_DISABLE_USER_CREATION", False):
            log.info("SOCIAL_AUTH_DISABLE_USER_CREATION setting is: True")
            # Check if user exists by email
            user_exists = User.objects.filter(email=email).exists() if email else False

            # Check if user exists by username (using email)
            username = email.split("@", 1)[0] if email else ""
            username_exists = (
                User.objects.filter(username=username).exists() if username else False
            )

            # Check if user exists by social auth
            google_id = response.get("sub", "")  # Google's unique user ID
            social_auth_exists = (
                UserSocialAuth.objects.filter(
                    provider=self.name, uid=google_id
                ).exists()
                if google_id
                else False
            )

            if not user_exists and not username_exists and not social_auth_exists:
                log.error(
                    f"User creation disabled and no existing user found for Google login. "
                    f"Email: {email}"
                )
                raise PermissionDenied(
                    "User creation is disabled. Please contact support if you need access."
                )

            log.info("Found existing user match for Google login")

        name, given_name, family_name = (
            response.get("name", ""),
            response.get("given_name", ""),
            response.get("family_name", ""),
        )
        fullname, first_name, last_name = self.get_user_names(
            name, given_name, family_name
        )

        # Get user details from existing user if available
        try:
            user = User.objects.get(email=email)
            log.info(f"Found existing user details for email: {email}")
            first_name = first_name or user.first_name
            last_name = last_name or user.last_name
        except User.DoesNotExist:
            log.info(f"No existing user found for email: {email}")
            pass

        user_details = {
            "username": email.split("@", 1)[0],  # Match default Google implementation
            "email": email,
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

        log.info("Successfully processed user details from Google")
        return user_details

    def get_user_id(self, details, response):
        """Use google 'sub' as unique id."""
        if self.setting("USE_UNIQUE_USER_ID", False):
            log.info("Using Google sub as unique user ID")
            return response.get("sub")

        log.info("Using email as user ID")
        return details.get("email")


def patch():
    """Patch the GoogleOAuth2 class with our implementation."""
    log.info("Applying IBLGoogleOAuth2 patch...")
    try:
        # Patch all possible import locations
        from social_core.backends import google

        log.info(f"Current GoogleOAuth2 class: {google.GoogleOAuth2}")

        # Patch the class
        google.GoogleOAuth2 = IBLGoogleOAuth2

        log.info(f"After patching GoogleOAuth2: {google.GoogleOAuth2}")

    except Exception as e:
        log.error(f"Error during patching: {str(e)}", exc_info=True)
        raise
