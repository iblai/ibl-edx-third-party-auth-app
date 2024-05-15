import pytest
from unittest.mock import patch as mock_patch, MagicMock
from common.djangoapps import third_party_auth
from ibl_third_party_auth.patches.patch_apple_id import IBLAppleIdAuth, patch

def test_patch():
    with mock_patch.object(third_party_auth.appleid, 'AppleIdAuth', create=True):
        patch()
        assert third_party_auth.appleid.AppleIdAuth == IBLAppleIdAuth

def test_auth_params():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    with mock_patch.object(ibl_auth, 'get_scope', return_value=True):
        params = ibl_auth.auth_params()
        assert params['response_mode'] == 'form_post'

def test_get_private_key():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    with mock_patch.object(ibl_auth, 'setting', return_value='dummy_value'):
        assert ibl_auth.get_private_key() == 'dummy_value'

def test_generate_client_secret():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    with mock_patch.object(ibl_auth, 'setting', return_value='dummy_value'):
        with mock_patch.object(ibl_auth, 'get_private_key', return_value='dummy_key'):
            with mock_patch('jwt.encode', return_value='dummy_token'):
                assert ibl_auth.generate_client_secret() == 'dummy_token'

def test_get_user_details():
    ibl_auth = IBLAppleIdAuth(strategy=None)
    response = {
        'name': {'firstName': 'John', 'lastName': 'Doe'},
        'email': 'john.doe@example.com',
        'sub': '1234567890'
    }
    with mock_patch.object(ibl_auth, 'setting', return_value=True):
        with mock_patch.object(ibl_auth, 'get_user_names', return_value=('John Doe', 'John', 'Doe')):
            user_details = ibl_auth.get_user_details(response)
            assert user_details['fullname'] == 'john.doe'
            assert user_details['first_name'] == 'John'
            assert user_details['last_name'] == 'Doe'
            assert user_details['email'] == 'john.doe@example.com'
            assert user_details['username'] == 'john.doe@example.com'