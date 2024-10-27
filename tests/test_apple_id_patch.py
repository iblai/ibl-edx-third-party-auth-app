import uuid
from unittest.mock import MagicMock
from unittest.mock import patch as mock_patch

import pytest
from common.djangoapps import third_party_auth
from ibl_third_party_auth.patches.patch_apple_id import IBLAppleIdAuth, patch
from jwt.exceptions import PyJWTError
from social_core.exceptions import AuthFailed, AuthStateMissing


@pytest.fixture
def mock_redis():
    with mock_patch("redis.Redis.from_url") as mock_redis:
        yield mock_redis


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


def test_get_and_store_state(mock_redis):
    ibl_auth = IBLAppleIdAuth(strategy=None)
    request = MagicMock()
    request.session.session_key = "test_session_key"

    with mock_patch("uuid.uuid4", return_value="dummy_state"):
        state = ibl_auth.get_and_store_state(request)
        mock_redis.return_value.setex.assert_called_once_with(
            "apple_auth_state:test_session_key", 300, "dummy_state"
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
