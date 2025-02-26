"""
Vendored from social-core:
https://github.com/python-social-auth/social-core/blob/master/social_core/backends/azuread.py

Additional changes:
- Added support for SOCIAL_AUTH_DISABLE_USER_CREATION setting
- Added enhanced logging
- Added user existence checks before creation
"""

import logging

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

    def get_user_details(self, response):
        """Return user details from Azure AD account."""
        log.info("Getting user details from Azure AD response")

        # Get email from the preferred_username which is usually the email
        email = response.get("preferred_username", "")
        if not email and response.get("email"):
            email = response.get("email")

        if not email:
            log.error("No email provided in Azure AD response")

        # Get name details from response
        name, given_name, family_name = (
            response.get("name", ""),
            response.get("given_name", ""),
            response.get("family_name", ""),
        )
        fullname, first_name, last_name = self.get_user_names(
            name, given_name, family_name
        )

        # Check if user creation is disabled and if the user exists
        if getattr(settings, "SOCIAL_AUTH_DISABLE_USER_CREATION", False):
            # Check if user exists by email
            user_exists = User.objects.filter(email=email).exists() if email else False

            # Check if user exists by username (using email)
            username = email.split("@", 1)[0] if email else ""
            username_exists = (
                User.objects.filter(username=username).exists() if username else False
            )

            # Check if user exists by social auth
            # Azure AD's unique user ID is in the 'oid' field
            azure_id = response.get("oid", "")
            social_auth_exists = (
                UserSocialAuth.objects.filter(provider=self.name, uid=azure_id).exists()
                if azure_id
                else False
            )

            if not user_exists and not username_exists and not social_auth_exists:
                log.error(
                    f"User creation disabled and no existing user found for Azure AD login. "
                    f"Checked email, username and social auth."
                )
                raise PermissionDenied(
                    "User creation is disabled. Please contact support if you need access."
                )

            log.info("Found existing user match for Azure AD login")

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
            "username": email.split("@", 1)[0],  # Match default implementation
            "email": email,
            "fullname": fullname,
            "first_name": first_name,
            "last_name": last_name,
        }

        log.info("Successfully processed user details from Azure AD")
        return user_details

    def get_user_id(self, details, response):
        """Use Azure AD's 'oid' as unique id."""
        if self.setting("USE_UNIQUE_USER_ID", False):
            log.info("Using Azure AD oid as unique user ID")
            return response.get("oid")

        log.info("Using email as user ID")
        return details.get("email")


def patch():
    """Patch the AzureADOAuth2 class with our implementation."""
    log.info("Applying IBLAzureADOAuth2 patch...")
    try:
        # Patch all possible import locations
        from social_core.backends import azuread

        log.info(f"Current AzureADOAuth2 class: {azuread.AzureADOAuth2}")

        # Patch the class
        azuread.AzureADOAuth2 = IBLAzureADOAuth2

        log.info(f"After patching AzureADOAuth2: {azuread.AzureADOAuth2}")

    except Exception as e:
        log.error(f"Error during patching: {str(e)}", exc_info=True)
        raise
