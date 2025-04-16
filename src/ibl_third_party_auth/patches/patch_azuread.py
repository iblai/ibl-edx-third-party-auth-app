"""
Vendored from social-core:
https://github.com/python-social-auth/social-core/blob/master/social_core/backends/azuread.py

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
from social_core.backends.azuread import AzureADOAuth2
from social_django.models import UserSocialAuth

log = logging.getLogger(__name__)


class IBLAzureADOAuth2(AzureADOAuth2):
    """
    Azure AD OAuth2 authentication backend with additional features:
    - Respects SOCIAL_AUTH_DISABLE_USER_CREATION setting
    - Enhanced logging
    - User existence checks
    """

    def get_user_details(self, response: Dict[str, Any]) -> Dict[str, str]:
        """Return user details from Azure AD account."""
        log.info("Processing Azure AD response")
        log.debug("Response keys", extra={"keys": list(response.keys())})

        # Get email from the preferred_username which is usually the email
        email = response.get("preferred_username", "")
        if not email and response.get("email"):
            email = response.get("email")

        if not email:
            log.error("Missing email in Azure AD response")
            raise PermissionDenied("Email is required for authentication")

        log.debug("Extracted email", extra={"email": email})

        # Get name details from response
        name, given_name, family_name = (
            response.get("name", ""),
            response.get("given_name", ""),
            response.get("family_name", ""),
        )
        fullname, first_name, last_name = self.get_user_names(
            name, given_name, family_name
        )
        log.debug(
            "Extracted name details",
            extra={
                "name": name,
                "given_name": given_name,
                "family_name": family_name,
                "fullname": fullname,
                "first_name": first_name,
                "last_name": last_name,
            },
        )

        # Check if user creation is disabled and if the user exists
        if getattr(settings, "SOCIAL_AUTH_DISABLE_USER_CREATION", False):
            log.info("User creation is disabled - checking for existing user")

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
            azure_id = response.get("oid", "")
            social_auth_exists = (
                UserSocialAuth.objects.filter(provider=self.name, uid=azure_id).exists()
                if azure_id
                else False
            )
            log.debug(
                "User existence check by social auth",
                extra={"azure_id": azure_id, "exists": social_auth_exists},
            )

            if not (user_exists or username_exists or social_auth_exists):
                log.error(
                    "User creation disabled and no existing user found",
                    extra={
                        "email": email,
                        "username": username,
                        "azure_id": azure_id,
                        "user_exists": user_exists,
                        "username_exists": username_exists,
                        "social_auth_exists": social_auth_exists,
                    },
                )
                raise PermissionDenied(
                    "User creation is disabled. Please contact support if you need access."
                )

            log.info("Found existing user match", extra={"email": email})

        # Get user details from existing user if available
        try:
            user = User.objects.get(email=email)
            log.info("Found existing user", extra={"email": email})
            first_name = first_name or user.first_name
            last_name = last_name or user.last_name
        except User.DoesNotExist:
            log.info("No existing user found", extra={"email": email})

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
        """Use Azure AD's 'oid' as unique id."""
        if self.setting("USE_UNIQUE_USER_ID", False):
            log.debug(
                "Using Azure AD oid as unique user ID",
                extra={"oid": response.get("oid")},
            )
            return response.get("oid")

        log.debug("Using email as user ID", extra={"email": details.get("email")})
        return details.get("email")


def patch() -> None:
    """Patch the AzureADOAuth2 class with our implementation."""
    log.info("Starting Azure AD patch application")
    try:
        from social_core.backends import azuread

        log.debug(
            "Current AzureADOAuth2 class", extra={"class": str(azuread.AzureADOAuth2)}
        )

        azuread.AzureADOAuth2 = IBLAzureADOAuth2
        log.info("Successfully patched AzureADOAuth2 class")

    except Exception as e:
        log.exception("Failed to apply Azure AD patch", extra={"error": str(e)})
        raise
