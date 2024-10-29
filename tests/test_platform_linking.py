import json
from unittest.mock import MagicMock, patch

from common.djangoapps.third_party_auth.models import OAuth2ProviderConfig
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from ibl_third_party_auth.management.commands.link_provider_users_to_platform import (
    Command,
)
from ibl_third_party_auth.utils.provider_utils import (
    get_monitored_provider,
    get_platform_key_from_provider,
    get_provider_config_by_backend,
)
from social_django.models import UserSocialAuth

User = get_user_model()


class TestPlatformLinking(TestCase):
    """Tests for the platform linking functionality."""

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.provider_config = OAuth2ProviderConfig.objects.create(
            name="Azure AD",
            slug="azuread-oauth2",
            backend_name="azuread-oauth2",
            enabled=True,
            other_settings=json.dumps(
                {
                    "platform_key": "test_platform",
                    "backend_uri": "/auth/login/azuread-oauth2",
                }
            ),
        )
        self.social_auth = UserSocialAuth.objects.create(
            user=self.user, provider="azuread-oauth2", uid="12345"
        )

    def test_get_provider_config(self):
        """Test getting provider configuration."""
        config = get_provider_config_by_backend("azuread-oauth2")
        self.assertIsNotNone(config)
        self.assertEqual(config.slug, "azuread-oauth2")

    def test_get_platform_key(self):
        """Test extracting platform key from provider config."""
        platform_key = get_platform_key_from_provider(self.provider_config)
        self.assertEqual(platform_key, "test_platform")

    def test_get_platform_key_invalid_json(self):
        """Test handling invalid JSON in provider config."""
        self.provider_config.other_settings = "invalid json"
        self.provider_config.save()
        platform_key = get_platform_key_from_provider(self.provider_config)
        self.assertIsNone(platform_key)

    @override_settings(AZURE_PROVIDER="custom-provider")
    def test_get_monitored_provider_custom(self):
        """Test getting custom monitored provider from settings."""
        provider = get_monitored_provider()
        self.assertEqual(provider, "custom-provider")

    def test_get_monitored_provider_default(self):
        """Test getting default monitored provider."""
        provider = get_monitored_provider()
        self.assertEqual(provider, "azuread-oauth2")

    @patch("ibl_third_party_auth.utils.user_platform_link.link_user_to_platform")
    def test_management_command(self, mock_link):
        """Test the management command for linking users."""
        mock_link.return_value = True

        command = Command()
        command.handle(provider="azuread-oauth2")

        mock_link.assert_called_once_with(self.user.id, "test_platform")

    @patch("ibl_third_party_auth.utils.user_platform_link.link_user_to_platform")
    def test_signal_handler(self, mock_link):
        """Test the signal handler for new social auth creation."""
        mock_link.return_value = True

        # Create a new social auth to trigger the signal
        new_user = User.objects.create_user(username="newuser", password="testpass")
        UserSocialAuth.objects.create(
            user=new_user, provider="azuread-oauth2", uid="67890"
        )

        mock_link.assert_called_once_with(new_user.id, "test_platform")

    @patch("ibl_third_party_auth.utils.user_platform_link.link_user_to_platform")
    def test_signal_handler_different_provider(self, mock_link):
        """Test the signal handler ignores non-monitored providers."""
        # Create a social auth with different provider
        new_user = User.objects.create_user(username="newuser", password="testpass")
        UserSocialAuth.objects.create(
            user=new_user, provider="google-oauth2", uid="67890"
        )

        mock_link.assert_not_called()

    @patch("ibl_third_party_auth.utils.user_platform_link.link_user_to_platform")
    def test_signal_handler_linking_failure(self, mock_link):
        """Test handling of linking failures in signal handler."""
        mock_link.return_value = False

        new_user = User.objects.create_user(username="newuser", password="testpass")
        UserSocialAuth.objects.create(
            user=new_user, provider="azuread-oauth2", uid="67890"
        )

        mock_link.assert_called_once_with(new_user.id, "test_platform")
