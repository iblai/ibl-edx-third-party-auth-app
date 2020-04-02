"""
Test the views served by third_party_auth.
"""

import mock
import json
import unittest

import ddt
import pytest
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase
from lxml import etree
from onelogin.saml2.errors import OneLogin_Saml2_Error
from openedx.core.djangoapps.site_configuration.tests.factories import SiteFactory
from crum import CurrentRequestUserMiddleware

from third_party_auth.tests.testutil import ThirdPartyAuthTestMixin
from third_party_auth.views import TPALogoutView, check_session_rp_iframe

from student.tests.factories import UserFactory
# Define some XML namespaces:
from third_party_auth.tasks import SAML_XML_NS


from .testutil import AUTH_FEATURE_ENABLED, AUTH_FEATURES_KEY, SAMLTestCase

XMLDSIG_XML_NS = 'http://www.w3.org/2000/09/xmldsig#'


@unittest.skipUnless(AUTH_FEATURE_ENABLED, AUTH_FEATURES_KEY + ' not enabled')
@ddt.ddt
class SAMLMetadataTest(SAMLTestCase):
    """
    Test the SAML metadata view
    """
    METADATA_URL = '/auth/saml/metadata.xml'

    def test_saml_disabled(self):
        """ When SAML is not enabled, the metadata view should return 404 """
        self.enable_saml(enabled=False)
        response = self.client.get(self.METADATA_URL)
        self.assertEqual(response.status_code, 404)

    def test_metadata(self):
        self.enable_saml()
        doc = self._fetch_metadata()
        # Check the ACS URL:
        acs_node = doc.find(".//{}".format(etree.QName(SAML_XML_NS, 'AssertionConsumerService')))
        self.assertIsNotNone(acs_node)
        self.assertEqual(acs_node.attrib['Location'], 'http://example.none/auth/complete/tpa-saml/')

    def test_default_contact_info(self):
        self.enable_saml()
        self.check_metadata_contacts(
            xml=self._fetch_metadata(),
            tech_name=u"{} Support".format(settings.PLATFORM_NAME),
            tech_email="technical@example.com",
            support_name=u"{} Support".format(settings.PLATFORM_NAME),
            support_email="technical@example.com"
        )

    def test_custom_contact_info(self):
        self.enable_saml(
            other_config_str=(
                '{'
                '"TECHNICAL_CONTACT": {"givenName": "Jane Tech", "emailAddress": "jane@example.com"},'
                '"SUPPORT_CONTACT": {"givenName": "Joe Support", "emailAddress": "joe@example.com"}'
                '}'
            )
        )
        self.check_metadata_contacts(
            xml=self._fetch_metadata(),
            tech_name="Jane Tech",
            tech_email="jane@example.com",
            support_name="Joe Support",
            support_email="joe@example.com"
        )

    @ddt.data(
        # Test two slightly different key pair export formats
        ('saml_key', 'MIICsDCCAhmgAw'),
        ('saml_key_alt', 'MIICWDCCAcGgAw'),
    )
    @ddt.unpack
    def test_signed_metadata(self, key_name, pub_key_starts_with):
        self.enable_saml(
            private_key=self._get_private_key(key_name),
            public_key=self._get_public_key(key_name),
            other_config_str='{"SECURITY_CONFIG": {"signMetadata": true} }',
        )
        self._validate_signed_metadata(pub_key_starts_with=pub_key_starts_with)

    def test_secure_key_configuration(self):
        """ Test that the SAML private key can be stored in Django settings and not the DB """
        self.enable_saml(
            public_key='',
            private_key='',
            other_config_str='{"SECURITY_CONFIG": {"signMetadata": true} }',
        )
        with self.assertRaises(OneLogin_Saml2_Error):
            self._fetch_metadata()  # OneLogin_Saml2_Error: Cannot sign metadata: missing SP private key.
        with self.settings(
            SOCIAL_AUTH_SAML_SP_PRIVATE_KEY=self._get_private_key('saml_key'),
            SOCIAL_AUTH_SAML_SP_PUBLIC_CERT=self._get_public_key('saml_key'),
        ):
            self._validate_signed_metadata()

    def _validate_signed_metadata(self, pub_key_starts_with='MIICsDCCAhmgAw'):
        """ Fetch the SAML metadata and do some validation """
        doc = self._fetch_metadata()
        sig_node = doc.find(".//{}".format(etree.QName(XMLDSIG_XML_NS, 'SignatureValue')))
        self.assertIsNotNone(sig_node)
        # Check that the right public key was used:
        pub_key_node = doc.find(".//{}".format(etree.QName(XMLDSIG_XML_NS, 'X509Certificate')))
        self.assertIsNotNone(pub_key_node)
        self.assertIn(pub_key_starts_with, pub_key_node.text)

    def _fetch_metadata(self):
        """ Fetch and parse the metadata XML at self.METADATA_URL """
        response = self.client.get(self.METADATA_URL)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/xml')
        # The result should be valid XML:
        try:
            metadata_doc = etree.fromstring(response.content)
        except etree.LxmlError:
            self.fail('SAML metadata must be valid XML')
        self.assertEqual(metadata_doc.tag, etree.QName(SAML_XML_NS, 'EntityDescriptor'))
        return metadata_doc

    def check_metadata_contacts(self, xml, tech_name, tech_email, support_name, support_email):
        """ Validate that the contact info in the metadata has the expected values """
        technical_node = xml.find(".//{}[@contactType='technical']".format(etree.QName(SAML_XML_NS, 'ContactPerson')))
        self.assertIsNotNone(technical_node)
        tech_name_node = technical_node.find(etree.QName(SAML_XML_NS, 'GivenName'))
        self.assertEqual(tech_name_node.text, tech_name)
        tech_email_node = technical_node.find(etree.QName(SAML_XML_NS, 'EmailAddress'))
        self.assertEqual(tech_email_node.text, tech_email)

        support_node = xml.find(".//{}[@contactType='support']".format(etree.QName(SAML_XML_NS, 'ContactPerson')))
        self.assertIsNotNone(support_node)
        support_name_node = support_node.find(etree.QName(SAML_XML_NS, 'GivenName'))
        self.assertEqual(support_name_node.text, support_name)
        support_email_node = support_node.find(etree.QName(SAML_XML_NS, 'EmailAddress'))
        self.assertEqual(support_email_node.text, support_email)


@unittest.skipUnless(AUTH_FEATURE_ENABLED, AUTH_FEATURES_KEY + ' not enabled')
class SAMLAuthTest(SAMLTestCase):
    """
    Test the SAML auth views
    """
    LOGIN_URL = '/auth/login/tpa-saml/'

    def test_login_without_idp(self):
        """ Accessing the login endpoint without an idp query param should return 302 """
        self.enable_saml()
        response = self.client.get(self.LOGIN_URL)
        self.assertEqual(response.status_code, 302)

    def test_login_disabled(self):
        """ When SAML is not enabled, the login view should return 404 """
        self.enable_saml(enabled=False)
        response = self.client.get(self.LOGIN_URL)
        self.assertEqual(response.status_code, 404)


class BaseTestCase(TestCase, ThirdPartyAuthTestMixin):
    @classmethod
    def setUpClass(cls):
        super(BaseTestCase, cls).setUpClass()
        cls.site = SiteFactory(domain='0.testserver.fake')
        cls.user = UserFactory()
        cls.factory = RequestFactory()

    @classmethod
    def _setup_request(cls, path):
        cls.base_request = cls.factory.get(path)
        cls.base_request.site = cls.site
        cls.base_request.user = cls.user

        # OAuth2ProviderConfig.enabled_for_current site uses crum and also
        # users request.get_host(), so need to set SERVER_NAME and use CRUM
        cls.base_request.META['SERVER_NAME'] = cls.site.domain
        crm = CurrentRequestUserMiddleware()
        crm.process_request(cls.base_request)

        cls.backend = cls.configure_keycloak_provider(
            enabled=True,
            visible=True,
            key='edx',
            site=cls.site,
            other_settings=json.dumps({
                'END_SESSION_URL': 'https://end.session.com/endpoint',
                'TARGET_OP': 'https://{}'.format(cls.site.domain),
                'CHECK_SESSION_URL': 'https://{}/check-session'.format(cls.site.domain),
            }))

    @pytest.fixture(autouse=True)
    def inject_fixtures(self, caplog):
        self._caplog = caplog


@mock.patch('third_party_auth.provider._PSA_OAUTH2_BACKENDS', ['keycloak'])
class TestTPALogoutView(BaseTestCase):
    """This class should only be touching the get_context_data function, so
    that is where we will focus our tests
    """
    @classmethod
    def setUpClass(cls):
        super(TestTPALogoutView, cls).setUpClass()
        cls._setup_request('/logout')

    @mock.patch('third_party_auth.views.TPA_LOGOUT_PROVIDER', None)
    def test_tpa_logout_provider_not_set_has_default_behavior(self):
        """If TPA_LOGOUT_PROVIDER is None, returns default behavior"""
        view = TPALogoutView()
        view.request = self.base_request
        context = view.get_context_data()
        context.pop('view')

        expected = {
            'logout_uris': [],
            'target': '/',
        }

        assert context == expected

    @mock.patch('third_party_auth.views.TPA_LOGOUT_PROVIDER', 'keycloak')
    @mock.patch('third_party_auth.views.TPALogoutView._add_post_logout_redirect_uri')
    def test_end_session_url_is_falsy_returns_default_behavior(self, add_uri_mock):
        """If final end_session_url is falsy, returns default behavior"""
        add_uri_mock.return_value = ''
        view = TPALogoutView()
        view.request = self.base_request
        context = view.get_context_data()
        context.pop('view')

        expected = {
            'logout_uris': [],
            'target': '/',
        }

        assert context == expected
        add_uri_mock.assert_called_once()

    @mock.patch('third_party_auth.views.TPA_LOGOUT_PROVIDER', 'keycloak')
    @mock.patch('third_party_auth.views.TPALogoutView._add_post_logout_redirect_uri')
    def test_end_session_url_has_value_replaces_target(self, add_uri_mock):
        """If final end_session_url is truthy, replaces target with that value"""
        add_uri_mock.return_value = 'https://somewhere.com'
        view = TPALogoutView()
        view.request = self.base_request
        context = view.get_context_data()
        context.pop('view')

        expected = {
            'logout_uris': [],
            'target': 'https://somewhere.com',
        }

        assert context == expected
        add_uri_mock.assert_called_once()

    @mock.patch('third_party_auth.views.TPA_LOGOUT_PROVIDER', 'empty')
    def test_tpa_logout_provider_not_found_returns_default_behavior(self):
        """If TPA_LOGOUT_PROVIDER backend not found, return default behavior"""
        view = TPALogoutView()
        view.request = self.base_request
        context = view.get_context_data()
        context.pop('view')

        expected = {
            'logout_uris': [],
            'target': '/',
        }

        assert context == expected
        assert 'defaulting to normal' in self._caplog.text


class TestTPALogoutViewAddPostLogoutRedirectUri(BaseTestCase):
    """Test the _add_post_logout_redirect_uri function of TPALogoutView"""
    @classmethod
    def setUpClass(cls):
        super(TestTPALogoutViewAddPostLogoutRedirectUri, cls).setUpClass()
        cls._setup_request('/logout')

    def test_no_end_session_url_returns_end_session_url(self):
        url = ''
        view = TPALogoutView()
        view.request = self.base_request
        end_session_url = view._add_post_logout_redirect_uri(url)
        assert end_session_url == ''

    @mock.patch('third_party_auth.views.TPA_POST_LOGOUT_REDIRECT_URL', None)
    def test_no_TPA_POST_LOGOUT_REDIRECT_URL_returns_end_session_url(self):
        url = 'https://end.session.com/'
        view = TPALogoutView()
        view.request = self.base_request
        end_session_url = view._add_post_logout_redirect_uri(url)
        assert end_session_url == url

    @mock.patch('third_party_auth.views.TPA_POST_LOGOUT_REDIRECT_URL', 'current_site')
    def test_redirect_to_current_site(self):
        """When TPA_POST_LOGOUT_REDIRECT_URL is 'current_site', add qs to current site"""
        url = 'https://end.session.com/'
        expected_url = 'https://end.session.com/?redirect_uri=https%3A%2F%2F0.testserver.fake'
        view = TPALogoutView()
        view.request = self.base_request
        end_session_url = view._add_post_logout_redirect_uri(url)
        assert end_session_url == expected_url

    @mock.patch('third_party_auth.views.TPA_POST_LOGOUT_REDIRECT_URL', 'https://my.site.com')
    def test_redirect_to_specific_site(self):
        """When TPA_POST_LOGOUT_REDIRECT_URL set to site, add qs to that site"""
        url = 'https://end.session.com/'
        expected_url = 'https://end.session.com/?redirect_uri=https%3A%2F%2Fmy.site.com'
        view = TPALogoutView()
        view.request = self.base_request
        end_session_url = view._add_post_logout_redirect_uri(url)
        assert end_session_url == expected_url

    @mock.patch('third_party_auth.views.TPA_POST_LOGOUT_REDIRECT_FIELD', 'next')
    @mock.patch('third_party_auth.views.TPA_POST_LOGOUT_REDIRECT_URL', 'https://my.site.com')
    def test_changing_redirect_url_query_string_param(self):
        """TPA_POST_LOGOUT_REDIRECT_FIELD is used instead of default 'redirect_ur'"""
        url = 'https://end.session.com/'
        expected_url = 'https://end.session.com/?next=https%3A%2F%2Fmy.site.com'
        view = TPALogoutView()
        view.request = self.base_request
        end_session_url = view._add_post_logout_redirect_uri(url)
        assert end_session_url == expected_url


class TestCheckSessionRPIframe(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(TestCheckSessionRPIframe, cls).setUpClass()
        cls._setup_request('/check-session-rp')

    @mock.patch('third_party_auth.views.TPA_LOGOUT_PROVIDER', None)
    def test_TPA_PROVIDER_is_none_returns_500(self):
        resp = check_session_rp_iframe(self.base_request)
        assert resp.status_code == 500
        assert "TPA_ENABLE_OP_SESSION_MANAGEMENT is True" in self._caplog.text

    @mock.patch('third_party_auth.views.TPA_LOGOUT_PROVIDER', 'keycloak')
    def test_non_authd_user_returns_404(self):
        self.base_request.session = {}
        self.base_request.user = AnonymousUser()
        resp = check_session_rp_iframe(self.base_request)
        assert resp.status_code == 404

    @mock.patch('third_party_auth.views.TPA_LOGOUT_PROVIDER', 'keycloak')
    def test_no_session_state_returns_404(self):
        self.base_request.session = {}
        resp = check_session_rp_iframe(self.base_request)
        assert resp.status_code == 404

    @mock.patch('third_party_auth.views.TPA_LOGOUT_PROVIDER', 'keycloak')
    @mock.patch('third_party_auth.views.provider.Registry.get_from_pipeline')
    def test_get_from_pipeline_is_none_returns_500(self, mock_from_pipeline):
        self.base_request.session = {'session_state': 'value'}
        mock_from_pipeline.return_value = None
        resp = check_session_rp_iframe(self.base_request)
        assert resp.status_code == 500
        assert "Expected backend" in self._caplog.text

    @mock.patch('third_party_auth.views.TPA_LOGOUT_PROVIDER', 'keycloak')
    def test_missing_provider_setting_returns_500(self):
        self.base_request.session = {'session_state': 'value'}

        # Missing TARGET_OP
        self.backend.other_settings = json.dumps({
            'END_SESSION_URL': 'https://end.session.com/endpoint',
            'CHECK_SESSION_URL': 'https://{}/check-session'.format(self.site.domain),
        })
        self.backend.save()
        resp = check_session_rp_iframe(self.base_request)
        assert resp.status_code == 500
        assert "Missing backend setting: 'TARGET_OP'" in self._caplog.text
        self._caplog.clear()

        # Missing CHECK_SESSION_URL
        self.backend.other_settings = json.dumps({
            'END_SESSION_URL': 'https://end.session.com/endpoint',
            'TARGET_OP': 'https://{}'.format(self.site.domain),
        })
        self.backend.save()
        resp = check_session_rp_iframe(self.base_request)
        assert resp.status_code == 500
        assert "Missing backend setting: 'CHECK_SESSION_URL'" in self._caplog.text
        self._caplog.clear()

    @mock.patch('third_party_auth.views.TPA_LOGOUT_PROVIDER', 'keycloak')
    def test_all_settings_correct_returns_200(self):
        self.base_request.session = {'session_state': 'value'}
        resp = check_session_rp_iframe(self.base_request)
        assert resp.status_code == 200
