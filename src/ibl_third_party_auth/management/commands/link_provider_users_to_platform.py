import json
import logging

from django.core.management.base import BaseCommand

from ibl_third_party_auth.utils.provider_utils import (
    get_provider_config_by_backend,
    get_social_auth_users_by_provider,
)
from ibl_third_party_auth.utils.user_platform_link import link_user_to_platform

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Links users from a specific provider to their corresponding platform using the Manager API"

    def add_arguments(self, parser):
        parser.add_argument(
            "provider", type=str, help="The provider name (e.g., azuread-oauth2)"
        )

    def handle(self, *args, **options):
        provider_name = options["provider"]

        # Get provider configuration
        provider_config = get_provider_config_by_backend(provider_name)
        if not provider_config:
            self.stderr.write(
                self.style.ERROR(
                    f"No enabled provider configuration found for {provider_name}"
                )
            )
            return

        # Get platform key from provider config
        try:
            other_settings = json.loads(provider_config.other_settings)
            platform_key = other_settings.get("platform_key")
            if not platform_key:
                self.stderr.write(
                    self.style.ERROR("No platform_key found in provider configuration")
                )
                return
        except json.JSONDecodeError:
            self.stderr.write(
                self.style.ERROR("Invalid JSON in provider other_settings")
            )
            return
        except Exception as e:
            self.stderr.write(
                self.style.ERROR(f"Error reading provider configuration: {str(e)}")
            )
            return

        # Get all users for this provider
        social_auth_users = get_social_auth_users_by_provider(provider_name)
        total_users = social_auth_users.count()

        if total_users == 0:
            self.stdout.write(
                self.style.WARNING(f"No users found for provider {provider_name}")
            )
            return

        self.stdout.write(f"Found {total_users} users for provider {provider_name}")

        # Process each user
        success_count = 0
        error_count = 0

        for index, social_auth in enumerate(social_auth_users, 1):
            user_id = social_auth.user.id

            self.stdout.write(f"Processing [{index}/{total_users}] User ID: {user_id}")

            try:
                result = link_user_to_platform(user_id, platform_key)
                if result:
                    success_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Successfully linked user {user_id} to platform {platform_key}"
                        )
                    )
                else:
                    error_count += 1
                    self.stdout.write(
                        self.style.ERROR(
                            f"Failed to link user {user_id} to platform {platform_key}"
                        )
                    )
            except Exception as e:
                error_count += 1
                self.stdout.write(
                    self.style.ERROR(f"Error processing user {user_id}: {str(e)}")
                )

        # Final summary
        self.stdout.write("\nOperation completed:")
        self.stdout.write(f"Total users processed: {total_users}")
        self.stdout.write(self.style.SUCCESS(f"Successful links: {success_count}"))
        self.stdout.write(self.style.ERROR(f"Failed links: {error_count}"))
