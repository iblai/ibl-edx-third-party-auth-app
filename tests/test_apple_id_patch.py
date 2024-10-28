import uuid
from unittest.mock import MagicMock
from unittest.mock import patch as mock_patch

import pytest
from common.djangoapps import third_party_auth
from ibl_third_party_auth.patches.patch_apple_id import (
    IBLAppleIdAuth,
    patch,
    verify_redis_cache,
)
from jwt.exceptions import PyJWTError
from social_core.exceptions import AuthFailed, AuthStateMissing


@pytest.fixture
def mock_redis():
    with mock_patch("redis.Redis.from_url") as mock_redis:
        yield mock_redis


@pytest.fixture
def mock_settings(monkeypatch):
    """Mock Django settings with Redis configuration."""
    mock_settings = MagicMock()
    mock_settings.CACHES = {
        "default": {
            "KEY_PREFIX": "default",
            "VERSION": "1",
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": "redis://@10.0.0.95:6479/1",
        }
    }
    monkeypatch.setattr("django.conf.settings", mock_settings)
    return mock_settings


@pytest.fixture
def mock_cache(monkeypatch):
    """Mock Django's cache."""
    mock_cache = MagicMock()
    monkeypatch.setattr("django.core.cache.cache", mock_cache)
    return mock_cache


def test_patch():
    with mock_patch.object(third_party_auth.appleid, "AppleIdAuth", create=True):
        patch()
        assert third_party_auth.appleid.AppleIdAuth == IBLAppleIdAuth


def test_auth_params():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    with mock_patch.object(ibl_auth, "get_scope", return_value=True):
        params = ibl_auth.auth_params()
        assert params["response_mode"] == "form_post"


def test_get_private_key():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    with mock_patch.object(ibl_auth, "setting", return_value="dummy_value"):
        assert ibl_auth.get_private_key() == "dummy_value"


def test_generate_client_secret():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    with mock_patch.object(ibl_auth, "setting", return_value="dummy_value"):
        with mock_patch.object(ibl_auth, "get_private_key", return_value="dummy_key"):
            with mock_patch("jwt.encode", return_value="dummy_token"):
                assert ibl_auth.generate_client_secret() == "dummy_token"


def test_get_user_details():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    response = {
        "name": {"firstName": "John", "lastName": "Doe"},
        "email": "john.doe@example.com",
        "sub": "1234567890",
    }
    with mock_patch.object(ibl_auth, "setting", return_value=True):
        with mock_patch.object(
            ibl_auth, "get_user_names", return_value=("John Doe", "John", "Doe")
        ):
            user_details = ibl_auth.get_user_details(response)
            assert user_details["fullname"] == "john.doe"
            assert user_details["first_name"] == "John"
            assert user_details["last_name"] == "Doe"
            assert user_details["email"] == "john.doe@example.com"
            assert user_details["username"] == "john.doe@example.com"


def test_get_and_store_state(mock_cache):
    """Test state storage using Django cache."""
    ibl_auth = IBLAppleIdAuth(strategy=None)
    request = MagicMock()
    request.session.session_key = "test_session_key"

    with mock_patch("uuid.uuid4", return_value="dummy_state"):
        state = ibl_auth.get_and_store_state(request)
        mock_cache.set.assert_called_once_with(
            "apple_auth_state:test_session_key", "dummy_state", timeout=300
        )
        assert state == "dummy_state"


def test_validate_state_success(mock_redis):
    ibl_auth = IBLAppleIdAuth(strategy=MagicMock())
    ibl_auth.strategy.session.session_key = "test_session_key"
    mock_redis.return_value.get.return_value = b"dummy_state"
    with mock_patch.object(ibl_auth, "get_request_state", return_value="dummy_state"):
        assert ibl_auth.validate_state() == "dummy_state"
        mock_redis.return_value.delete.assert_called_once_with(
            "apple_auth_state:test_session_key"
        )


def test_validate_state_missing(mock_redis):
    ibl_auth = IBLAppleIdAuth(strategy=MagicMock())
    ibl_auth.strategy.session.session_key = "test_session_key"
    mock_redis.return_value.get.return_value = None
    with mock_patch.object(ibl_auth, "get_request_state", return_value="dummy_state"):
        with pytest.raises(AuthStateMissing):
            ibl_auth.validate_state()


def test_validate_state_mismatch(mock_redis):
    ibl_auth = IBLAppleIdAuth(strategy=MagicMock())
    ibl_auth.strategy.session.session_key = "test_session_key"
    mock_redis.return_value.get.return_value = b"stored_state"
    with mock_patch.object(
        ibl_auth, "get_request_state", return_value="different_state"
    ):
        with pytest.raises(AuthStateMissing):
            ibl_auth.validate_state()


def test_generate_client_secret_success():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    with mock_patch.object(ibl_auth, "setting", return_value="dummy_value"):
        with mock_patch.object(ibl_auth, "get_private_key", return_value="dummy_key"):
            with mock_patch("jwt.encode", return_value="dummy_token"):
                assert ibl_auth.generate_client_secret() == "dummy_token"


def test_generate_client_secret_failure():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    with mock_patch.object(ibl_auth, "setting", return_value="dummy_value"):
        with mock_patch.object(ibl_auth, "get_private_key", return_value="dummy_key"):
            with mock_patch("jwt.encode", side_effect=Exception("JWT encoding failed")):
                with pytest.raises(Exception, match="JWT encoding failed"):
                    ibl_auth.generate_client_secret()


def test_decode_id_token_success():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    with mock_patch("jwt.get_unverified_header", return_value={"kid": "dummy_kid"}):
        with mock_patch.object(ibl_auth, "get_apple_jwk", return_value="dummy_jwk"):
            with mock_patch("jwt.decode", return_value={"sub": "dummy_sub"}):
                assert ibl_auth.decode_id_token("dummy_token") == {"sub": "dummy_sub"}


def test_decode_id_token_failure():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    with mock_patch("jwt.get_unverified_header", return_value={"kid": "dummy_kid"}):
        with mock_patch.object(ibl_auth, "get_apple_jwk", return_value="dummy_jwk"):
            with mock_patch(
                "jwt.decode", side_effect=PyJWTError("Token validation failed")
            ):
                with pytest.raises(AuthFailed, match="Token validation failed"):
                    ibl_auth.decode_id_token("dummy_token")


def test_patch_is_applied():
    """Test that the patch is correctly applied to the AppleIdAuth class."""
    from common.djangoapps.third_party_auth import appleid
    from ibl_third_party_auth.patches.patch_apple_id import IBLAppleIdAuth, patch

    # Store original class
    original_class = appleid.AppleIdAuth

    try:
        # Apply patch
        patch()

        # Verify patch was applied
        assert appleid.AppleIdAuth == IBLAppleIdAuth
        assert appleid.AppleIdAuth.name == "apple-id"

    finally:
        # Restore original class
        appleid.AppleIdAuth = original_class


def test_get_redis_client(mock_settings):
    """Test Redis client creation with Open edX settings."""
    from ibl_third_party_auth.patches.patch_apple_id import get_redis_client

    with mock_patch("redis.Redis.from_url") as mock_redis:
        client = get_redis_client()
        mock_redis.assert_called_once_with(
            "redis://@10.0.0.95:6479/1", decode_responses=True, socket_timeout=5
        )
        assert client == mock_redis.return_value


def test_get_redis_client_url_fallback(mock_settings):
    """Test Redis client falls back to explicit parameters if URL connection fails."""
    from ibl_third_party_auth.patches.patch_apple_id import get_redis_client

    with mock_patch(
        "redis.Redis.from_url", side_effect=Exception("URL connection failed")
    ):
        with mock_patch("redis.Redis") as mock_redis:
            client = get_redis_client()
            mock_redis.assert_called_once_with(
                host="10.0.0.95",
                port=6479,
                db=1,
                password=None,
                socket_timeout=5,
                decode_responses=True,
            )
            assert client == mock_redis.return_value


def test_get_redis_client_no_config(mock_settings):
    """Test Redis client raises exception when no Redis configuration is found."""
    from ibl_third_party_auth.patches.patch_apple_id import get_redis_client

    # Remove Redis configuration
    mock_settings.CACHES = {}

    with pytest.raises(
        Exception, match="Redis cache configuration not found in settings"
    ):
        get_redis_client()


def test_request_access_token():
    """Test request_access_token properly includes client_secret in data."""
    ibl_auth = IBLAppleIdAuth(strategy=None)

    with mock_patch.object(
        ibl_auth, "generate_client_secret", return_value="test_secret"
    ):
        with mock_patch.object(
            ibl_auth,
            "request_access_token",
            return_value={"access_token": "test_token"},
        ):
            # Test with dict data
            kwargs = {"data": {"code": "test_code"}}
            response = ibl_auth.request_access_token(**kwargs)
            assert kwargs["data"]["client_secret"] == "test_secret"

            # Test with string data
            kwargs = {"data": "code=test_code"}
            response = ibl_auth.request_access_token(**kwargs)
            assert isinstance(kwargs["data"], dict)
            assert kwargs["data"]["client_secret"] == "test_secret"
            assert kwargs["data"]["code"] == "test_code"


def test_verify_redis_cache(mock_settings):
    """Test Redis cache verification."""
    from ibl_third_party_auth.patches.patch_apple_id import verify_redis_cache

    # Test with Redis backend
    assert verify_redis_cache() is True

    # Test with different backend
    mock_settings.CACHES["default"]["BACKEND"] = (
        "django.core.cache.backends.locmem.LocMemCache"
    )
    assert verify_redis_cache() is False

    # Test with no cache config
    mock_settings.CACHES = {}
    assert verify_redis_cache() is False


def test_get_and_store_state_no_redis(mock_settings, mock_cache):
    """Test state storage falls back to session when Redis is not available."""
    mock_settings.CACHES["default"]["BACKEND"] = (
        "django.core.cache.backends.locmem.LocMemCache"
    )

    ibl_auth = IBLAppleIdAuth(strategy=None)
    request = MagicMock()
    request.session.session_key = "test_session_key"

    with mock_patch("uuid.uuid4", return_value="dummy_state"):
        state = ibl_auth.get_and_store_state(request)
        mock_cache.set.assert_not_called()
        assert state == "dummy_state"
        assert request.session["apple_auth_state"] == "dummy_state"
