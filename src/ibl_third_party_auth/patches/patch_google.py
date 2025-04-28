"""
Vendored from social-core:
https://github.com/python-social-auth/social-core/blob/master/social_core/backends/google.py

Additional changes:
- Added support for SOCIAL_AUTH_DISABLE_USER_CREATION setting
- Added enhanced logging
- Added user existence checks before creation
"""

import logging
from typing import Any, Dict, Optional

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

    def get_user_details(self, response: Dict[str, Any]) -> Dict[str, str]:
        """Return user details from Google API account."""
        log.debug(
            "Processing Google OAuth2 response",
            extra={"response_keys": list(response.keys())},
        )

        if not response.get("email"):
            log.error("Authentication failed: No email in Google response")
            raise PermissionDenied("Email is required for authentication")

        # Get basic details from response
        email = response.get("email", "")
        log.debug("Extracted email from response", extra={"email": email})

        # Check if user creation is disabled and if the user exists
        if getattr(settings, "SOCIAL_AUTH_DISABLE_USER_CREATION", False):
            log.info(
                "User creation is disabled - checking for existing user",
                extra={"email": email},
            )

            # Check if user exists by email
            user_exists = User.objects.filter(email=email).exists() if email else False
            log.debug("User existence check by email", extra={"exists": user_exists})

            # Check if user exists by username (using email)
            username = email.split("@", 1)[0] if email else ""
            username_exists = (
                User.objects.filter(username=username).exists() if username else False
            )
            log.debug(
                "User existence check by username",
                extra={"username": username, "exists": username_exists},
            )

            # Check if user exists by social auth
            google_id = response.get("sub", "")
            social_auth_exists = (
                UserSocialAuth.objects.filter(
                    provider=self.name, uid=google_id
                ).exists()
                if google_id
                else False
            )
            log.debug(
                "User existence check by social auth",
                extra={"google_id": google_id, "exists": social_auth_exists},
            )

            if not (user_exists or username_exists or social_auth_exists):
                log.error(
                    "User creation disabled and no existing user found",
                    extra={
                        "email": email,
                        "username": username,
                        "google_id": google_id,
                        "user_exists": user_exists,
                        "username_exists": username_exists,
                        "social_auth_exists": social_auth_exists,
                    },
                )
                raise PermissionDenied(
                    "User creation is disabled. Please contact support if you need access."
                )

            log.info("Found existing user match", extra={"email": email})

        # Get user details from response
        name, given_name, family_name = (
            response.get("name", ""),
            response.get("given_name", ""),
            response.get("family_name", ""),
        )
        fullname, first_name, last_name = self.get_user_names(
            name, given_name, family_name
        )
        log.debug(
            "Extracted user details",
            extra={
                "name": name,
                "given_name": given_name,
                "family_name": family_name,
                "fullname": fullname,
                "first_name": first_name,
                "last_name": last_name,
            },
        )

        # Get user details from existing user if available
        try:
            user = User.objects.get(email=email)
            log.info("Found existing user", extra={"email": email})
            first_name = first_name or user.first_name
            last_name = last_name or user.last_name
        except User.DoesNotExist:
            log.info("No existing user found", extra={"email": email})
            if getattr(settings, "SOCIAL_AUTH_DISABLE_USER_CREATION", False):
                log.error("User existence check inconsistency", extra={"email": email})
                raise PermissionDenied(
                    "An error occurred during authentication. Please contact support."
                )

        user_details = {
            "username": email.split("@", 1)[0],
            "email": email,
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }
        log.debug("Final user details", extra={"user_details": user_details})
        return user_details

    def get_user_id(self, details: Dict[str, str], response: Dict[str, Any]) -> str:
        """Use google 'sub' as unique id."""
        if self.setting("USE_UNIQUE_USER_ID", False):
            log.debug(
                "Using Google sub as unique user ID", extra={"sub": response.get("sub")}
            )
            return response.get("sub")

        log.debug("Using email as user ID", extra={"email": details.get("email")})
        return details.get("email")


def patch():
    """Patch the GoogleOAuth2 class with our implementation."""
    log.info("Starting Google OAuth2 patch application")
    try:
        from social_core.backends import google

        log.debug(
            "Current GoogleOAuth2 class", extra={"class": str(google.GoogleOAuth2)}
        )

        google.GoogleOAuth2 = IBLGoogleOAuth2
        log.info("Successfully patched GoogleOAuth2 class")

    except Exception as e:
        log.exception("Failed to apply Google OAuth2 patch", extra={"error": str(e)})
        raise
