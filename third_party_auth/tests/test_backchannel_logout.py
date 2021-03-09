import mock
import pytest

from django.contrib.auth.models import User
from student.tests.factories import UserFactory

from third_party_auth.tests.test_views import BaseTestCase
from third_party_auth import backchannel_logout as bcl


@pytest.fixture(autouse=True)
def autouse_db(db):
    pass


@pytest.fixture
def user():
    email = 'someone@test.com'
    user = UserFactory(username=email, email=email)
    return user


def test_get_profile_from_sub_returns_profile(user):
    """If sub has format f:<something>:username, returns profile for username"""
    email = 'someone@test.com'
    sub = 'f:something:{}'.format(email)
    found_user = bcl._get_user_from_sub(sub)
    assert found_user == user


def test_get_profile_from_sub_raises_not_found(user):
    """If username not found, raises DoesNotExist"""
    email = 'not_found@test.com'
    sub = 'f:something:{}'.format(email)
    with pytest.raises(User.DoesNotExist):
        profile = bcl._get_user_from_sub(sub)


@pytest.mark.skip
def test_get_backchannel_logout_response_sets_status():
    pass


@pytest.mark.skip
def test_get_current_provider():
    pass


@pytest.mark.skip
def test_logout_of_sessions_no_sessions_exist():
    pass


@pytest.mark.skip
def test_logout_of_sessions_all_sessions_deleted():
    pass


@pytest.mark.skip
@mock.patch('third_party_auth.provider._PSA_OAUTH2_BACKENDS', ['keycloak'])
class TestBackchannelLogoutView(BaseTestCase):
    pass
