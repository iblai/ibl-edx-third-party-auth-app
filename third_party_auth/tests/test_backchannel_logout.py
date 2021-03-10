import json
import mock
import pytest

from django.conf import settings
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth import login
from django.test import RequestFactory, TestCase, override_settings
from third_party_auth.tests.testutil import ThirdPartyAuthTestMixin

from crum import CurrentRequestUserMiddleware
from student.tests.factories import UserFactory
from openedx.core.djangoapps.site_configuration.tests.factories import SiteFactory
from jwt.exceptions import InvalidTokenError

from third_party_auth import backchannel_logout as bcl
from third_party_auth.jwt_validation import JwtValidationError

from social_django.models import UserSocialAuth

LMS_FEATURES = settings.FEATURES.copy()
LMS_FEATURES['PREVENT_CONCURRENT_LOGINS'] = True


@pytest.fixture(autouse=True)
def autouse_db(db):
    pass


@pytest.fixture
def user():
    email = 'someone@test.com'
    user = UserFactory(username=email, email=email)
    return user


class BaseTestCase(TestCase, ThirdPartyAuthTestMixin):
    @classmethod
    def setUpClass(cls):
        super(BaseTestCase, cls).setUpClass()
        cls.site = SiteFactory(domain='0.testserver.fake')
        cls.factory = RequestFactory()
        cls.url = reverse('tpa-backchannel-logout', kwargs={'backend': 'keycloak'})
        cls.provider = 'keycloak'

    def setUp(self):
        self.user = UserFactory()

    def _setup_request(self, path, post_dict):
        self.request = self.factory.post(path, post_dict)
        self.request.site = self.site

        # OAuth2ProviderConfig.enabled_for_current site uses crum and also
        # users request.get_host(), so need to set SERVER_NAME and use CRUM
        self.request.META['SERVER_NAME'] = self.site.domain
        crm = CurrentRequestUserMiddleware()
        crm.process_request(self.request)

        self.backend = self.configure_keycloak_provider(
            enabled=True,
            visible=True,
            key='edx',
            site=self.site,
            other_settings=json.dumps({
                'PUBLIC_KEY': 'test',
                'ISS': 'https://auth.com',
                'END_SESSION_URL': 'https://end.session.com/endpoint',
                'TARGET_OP': 'https://{}'.format(self.site.domain),
                'CHECK_SESSION_URL': 'https://{}/check-session'.format(self.site.domain),
            }))

    @pytest.fixture(autouse=True)
    def inject_fixtures(self, caplog):
        self._caplog = caplog


def test_get_profile_from_sub_returns_profile(user):
    """If sub has format f:<something>:username, returns profile for username"""
    email = 'someone@test.com'
    provider = 'keycloak'
    UserSocialAuth.objects.create(uid=email, provider=provider, user=user)
    sub = 'f:something:{}'.format(email)
    found_user = bcl._get_user_from_sub(sub, provider)
    assert found_user == user


def test_get_profile_from_sub_raises_not_found(user):
    """If username not found, raises DoesNotExist"""
    email = 'not_found@test.com'
    provider = 'keycloak'
    sub = 'f:something:{}'.format(email)
    with pytest.raises(UserSocialAuth.DoesNotExist):
        bcl._get_user_from_sub(sub, provider)


def test_get_profile_from_sub_raises_multiple_found(user):
    """If multiple objects with UID"""
    email = 'not_found@test.com'
    provider = 'keycloak'
    sub = 'f:something:{}'.format(email)
    with pytest.raises(UserSocialAuth.DoesNotExist):
        bcl._get_user_from_sub(sub, provider)


@pytest.mark.skip
def test_get_backchannel_logout_response_sets_status():
    pass


@pytest.mark.skip
def test_get_current_provider():
    pass


@mock.patch('third_party_auth.provider._PSA_OAUTH2_BACKENDS', ['keycloak'])
class TestBackchannelLogoutView(BaseTestCase):

    def test_token_not_provided_returns_400(self):
        """Test no logout_token provided then returns 400"""
        self._setup_request(self.url, {})
        resp = bcl.back_channel_logout(self.request, self.provider)
        assert resp.status_code == 400

    def test_no_providers_available_returns_500(self):
        """If no providers are available for backend, returns 501"""
        self._setup_request(self.url, {'logout_token': 'something'})
        self.backend.delete()
        resp = bcl.back_channel_logout(self.request, self.provider)
        assert resp.status_code == 501
        assert "No or Multiple" in self._caplog.messages[-1]

    def test_more_than_1_provider_available_returns_500(self):
        """If > 1 provider is found, return 501"""
        self._setup_request(self.url, {'logout_token': 'something'})
        self.configure_keycloak_provider(
            enabled=True,
            visible=True,
            slug="edx",
            key='edx',
            site=self.site,
            other_settings=json.dumps({
                'PUBLIC_KEY': 'test',
                'ISS': 'https://auth.com',
                'END_SESSION_URL': 'https://end.session.com/endpoint2',
                'TARGET_OP': 'https://{}'.format(self.site.domain),
                'CHECK_SESSION_URL': 'https://{}/check-session2'.format(self.site.domain),
            }))
        resp = bcl.back_channel_logout(self.request, self.provider)
        assert resp.status_code == 501
        assert "No or Multiple" in self._caplog.messages[-1]

    @mock.patch('third_party_auth.backchannel_logout.jwt_validation.validate_jwt')
    def test_validate_jwt_invalid_token_error_returns_400(self, mock_jwt_val):
        """If InvalidTokenError is raised it returns a 400"""
        mock_jwt_val.side_effect = InvalidTokenError('Bad things Mikey, bad things')
        self._setup_request(self.url, {'logout_token': 'something'})
        resp = bcl.back_channel_logout(self.request, self.provider)
        assert resp.status_code == 400
        assert "Bad things Mikey" in self._caplog.messages[-1]

    @mock.patch('third_party_auth.backchannel_logout.jwt_validation.validate_jwt')
    def test_validate_jwt_jwt_validation_error_returns_400(self, mock_jwt_val):
        """If JwtValidationError is raised it returns a 400"""
        mock_jwt_val.side_effect = JwtValidationError('Bad things Mikey, bad things')
        self._setup_request(self.url, {'logout_token': 'something'})
        resp = bcl.back_channel_logout(self.request, self.provider)
        assert resp.status_code == 400
        assert "Bad things Mikey" in self._caplog.messages[-1]

    @mock.patch('third_party_auth.backchannel_logout.jwt_validation.validate_jwt')
    def test_validate_jwt_any_other_exception_returns_501(self, mock_jwt_val):
        """If any other exception occurs in validate_jwt, return a 501"""
        mock_jwt_val.side_effect = ValueError('Bad things Mikey, bad things')
        self._setup_request(self.url, {'logout_token': 'something'})
        resp = bcl.back_channel_logout(self.request, self.provider)
        assert resp.status_code == 501
        assert "Bad things Mikey" in self._caplog.messages[-1]

    @mock.patch('third_party_auth.backchannel_logout._get_user_from_sub')
    @mock.patch('third_party_auth.backchannel_logout.jwt_validation.validate_jwt')
    def test_no_social_auth_exists_returns_501(self, mock_jwt_val, mock_user_sub):
        """If UserSocialAuth.DoesNotExist raised, return 501"""
        mock_jwt_val.return_value = {'sub': 'f:something:not_found@test.com'}
        mock_user_sub.side_effect = UserSocialAuth.DoesNotExist()

        self._setup_request(self.url, {'logout_token': 'something'})
        resp = bcl.back_channel_logout(self.request, self.provider)
        assert resp.status_code == 501
        assert "No UserSocialAuth" in self._caplog.messages[-1]

    @mock.patch('third_party_auth.backchannel_logout._get_user_from_sub')
    @mock.patch('third_party_auth.backchannel_logout.jwt_validation.validate_jwt')
    def test_logout_of_sessions_succeeds_returns_200(self, mock_jwt_val, mock_user_sub):
        """If user has no active sessions, returns 200 and profile meta not changed"""
        mock_jwt_val.return_value = {'sub': 'f:something:not_found@test.com'}
        mock_user_sub.return_value = self.user

        self._setup_request(self.url, {'logout_token': 'something'})
        resp = bcl.back_channel_logout(self.request, self.provider)
        assert resp.status_code == 200


class TestLogoutOfSessions(BaseTestCase):

    @override_settings(FEATURES=LMS_FEATURES)
    def test_no_active_sessions_profile_not_touched(self):
        """If no active sessions, user's profile not changed and warning logged"""
        self._setup_request(self.url, {'logout_token': 'something'})
        assert self.user.profile.get_meta() == {}

        bcl._logout_of_sessions(self.user, self.request)
        self.user.profile.refresh_from_db()
        assert self.user.profile.get_meta() == {}
        assert "Logout request sent" in self._caplog.messages[-1]

    @override_settings(FEATURES=LMS_FEATURES)
    @mock.patch('third_party_auth.backchannel_logout.user_logged_out')
    def test_lms_active_session_is_removed(self, mock_logged_out):
        """If active LMS session, it's removed from profile and user logged out"""
        self.client.force_login(self.user)
        # Client now has a session in the lms
        self.user.profile.refresh_from_db()
        assert self.user.profile.get_meta().get('session_id') is not None
        assert 'cms_session_id' not in self.user.profile.get_meta()

        self._setup_request(self.url, {'logout_token': 'something'})
        bcl._logout_of_sessions(self.user, self.request)

        mock_logged_out.send.assert_called_once()
        assert self.user.profile.get_meta() == {'session_id': None}

    @override_settings(IBL_CMS_PREVENT_CONCURRENT_LOGINS=True)
    @mock.patch('third_party_auth.backchannel_logout.user_logged_out')
    def test_cms_active_session_is_removed(self, mock_logged_out):
        """If active CMS session, it's removed from profile and user logged out"""
        self.client.force_login(self.user)
        self.user.profile.refresh_from_db()
        # Client now has a session in the cms
        assert self.user.profile.get_meta().get('cms_session_id') is not None
        assert 'session_id' not in self.user.profile.get_meta()

        self._setup_request(self.url, {'logout_token': 'something'})
        bcl._logout_of_sessions(self.user, self.request)

        mock_logged_out.send.assert_called_once()
        assert self.user.profile.get_meta() == {'cms_session_id': None}
