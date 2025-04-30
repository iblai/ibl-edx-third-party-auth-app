import datetime
import random
import secrets
import uuid
from datetime import timedelta

import factory
from common.djangoapps.student.tests.factories import UserFactory
from django.conf import settings
from django.utils import timezone
from factory.django import DjangoModelFactory
from oauth2_provider.models import (
    get_access_token_model,
    get_application_model,
    get_grant_model,
)

Application = get_application_model()
AccessToken = get_access_token_model()
Grant = get_grant_model()


class DMTokenResponseFactory(factory.DictFactory):
    token = factory.LazyFunction(lambda: secrets.token_urlsafe(16))
    expiry = factory.LazyFunction(
        lambda: (
            datetime.datetime.now() + datetime.timedelta(hours=random.randint(1, 5))
        ).isoformat()
    )


class UserFactory(DjangoModelFactory):
    class Meta:
        model = settings.AUTH_USER_MODEL  # Use the configured user model

    username = factory.Sequence(lambda n: f"user_{n}")
    email = factory.LazyAttribute(lambda o: f"{o.username}@example.com")
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    is_staff = False
    is_active = True

    # Use post-generation hook for setting password if needed for login tests
    @factory.post_generation
    def password(self, create, extracted, **kwargs):
        if not create:
            # Simple build, do nothing.
            return
        # Use a default password if none is provided
        password = extracted or "default_password"
        self.set_password(password)
        self.save()  # Save again after setting password


# --- Application Factory ---
class ApplicationFactory(DjangoModelFactory):
    """
    Factory for oauth2_provider.models.Application.
    Creates a confidential client application allowing authorization code grant by default.
    """

    class Meta:
        model = Application

    # Associate with a user (e.g., the owner/developer of the application)
    # If you don't need a specific user owner, you can set user=None
    # if your Application model allows it (check null=True on the user field).
    # Usually, an Application requires a user.
    user = factory.SubFactory(UserFactory)

    # Sensible defaults for common use cases
    client_type = Application.CLIENT_CONFIDENTIAL
    authorization_grant_type = Application.GRANT_AUTHORIZATION_CODE

    # Application name
    name = factory.Sequence(lambda n: f"Test Application {n}")

    # Redirect URIs - can be a space-separated string of URIs
    # Often needed for authorization code flow.
    redirect_uris = "https://example.com/callback http://localhost:8000/callback"

    # client_id and client_secret are usually generated automatically by
    # django-oauth-toolkit upon saving, so we don't typically define them here.
    # skip_authorization = False # Default is False


# --- AccessToken Factory ---
class AccessTokenFactory(DjangoModelFactory):
    """
    Factory for oauth2_provider.models.AccessToken.
    Creates an access token associated with a user and application.
    """

    class Meta:
        model = AccessToken

    # Link to a user (the resource owner granting access)
    user = factory.SubFactory(UserFactory)

    # Link to the client application the token is granted for
    application = factory.SubFactory(ApplicationFactory)

    # The token string itself - DOT usually generates this.
    # If you need predictable tokens for testing, uncomment and use Sequence/LazyFunction.
    # token = factory.Sequence(lambda n: f"test_token_{n}")
    # Or use UUID for uniqueness:
    token = factory.LazyFunction(lambda: uuid.uuid4().hex)

    # Define the scope of the token (space-separated strings)
    scope = "read write"  # Adjust as needed for your application's scopes

    # Set an expiration date - typically slightly in the future
    expires = factory.LazyFunction(lambda: timezone.now() + timedelta(hours=1))

    # source_refresh_token = None # Optional: Link to a RefreshToken instance if needed


# --- Grant Factory (Authorization Code) ---
class GrantFactory(DjangoModelFactory):
    """
    Factory for oauth2_provider.models.Grant.
    Represents an authorization code grant.
    """

    class Meta:
        model = Grant

    user = factory.SubFactory(UserFactory)
    application = factory.SubFactory(ApplicationFactory)

    # The authorization code - DOT usually generates this.
    # code = factory.Sequence(lambda n: f"auth_code_{n}")
    code = factory.LazyFunction(
        lambda: uuid.uuid4().hex[:10]
    )  # Example: Generate a short code

    expires = factory.LazyFunction(
        lambda: timezone.now()
        + timedelta(minutes=10)  # Auth codes usually have short expiry
    )
    redirect_uri = factory.LazyAttribute(
        lambda o: o.application.redirect_uris.split()[0]
    )  # Use first redirect URI from app
    scope = "read"  # Default scope for the grant
