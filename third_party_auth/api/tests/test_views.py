"""
Tests for the Third Party Auth REST API
"""
import copy
import json
import unittest

import ddt
import six
from django.conf import settings
from django.http import QueryDict
from django.test.utils import override_settings
from django.urls import reverse
from mock import patch
from provider.constants import CONFIDENTIAL
from provider.oauth2.models import Client, AccessToken
from openedx.core.djangoapps.site_configuration.tests.factories import SiteFactory
from openedx.core.lib.api.permissions import ApiKeyHeaderPermission
from rest_framework.test import APITestCase
from social_django.models import UserSocialAuth

from student.tests.factories import UserFactory
from third_party_auth.api.permissions import ThirdPartyAuthProviderApiPermission
from third_party_auth.models import ProviderApiPermissions, OAuth2ProviderConfig
from third_party_auth.tests.testutil import ThirdPartyAuthTestMixin

import pytest


VALID_API_KEY = "i am a key"
IDP_SLUG_TESTSHIB = 'testshib'
PROVIDER_ID_TESTSHIB = 'saml-' + IDP_SLUG_TESTSHIB

ALICE_USERNAME = "alice"
CARL_USERNAME = "carl"
STAFF_USERNAME = "staff"
ADMIN_USERNAME = "admin"
NONEXISTENT_USERNAME = "nobody"
# These users will be created and linked to third party accounts:
LINKED_USERS = (ALICE_USERNAME, STAFF_USERNAME, ADMIN_USERNAME)
PASSWORD = "edx"


def get_mapping_data_by_usernames(usernames):
    """ Generate mapping data used in response """
    return [{'username': username, 'remote_id': 'remote_' + username} for username in usernames]


class TpaAPITestCase(ThirdPartyAuthTestMixin, APITestCase):
    """ Base test class """

    def setUp(self):
        """ Create users for use in the tests """
        super(TpaAPITestCase, self).setUp()

        google = self.configure_google_provider(enabled=True)
        self.configure_facebook_provider(enabled=True)
        self.configure_linkedin_provider(enabled=False)
        self.enable_saml()
        testshib = self.configure_saml_provider(
            name='TestShib',
            enabled=True,
            slug=IDP_SLUG_TESTSHIB
        )

        # Create several users and link each user to Google and TestShib
        for username in LINKED_USERS:
            make_superuser = (username == ADMIN_USERNAME)
            make_staff = (username == STAFF_USERNAME) or make_superuser
            user = UserFactory.create(
                username=username,
                email='{}@example.com'.format(username),
                password=PASSWORD,
                is_staff=make_staff,
                is_superuser=make_superuser,
            )
            UserSocialAuth.objects.create(
                user=user,
                provider=google.backend_name,
                uid='{}@gmail.com'.format(username),
            )
            UserSocialAuth.objects.create(
                user=user,
                provider=testshib.backend_name,
                uid='{}:remote_{}'.format(testshib.slug, username),
            )
        # Create another user not linked to any providers:
        UserFactory.create(username=CARL_USERNAME, email='{}@example.com'.format(CARL_USERNAME), password=PASSWORD)


@ddt.ddt
class UserViewsMixin(object):
    """
    Generic TestCase to exercise the v1 and v2 UserViews.
    """

    def expected_active(self, username):
        """ The JSON active providers list response expected for the given user """
        if username not in LINKED_USERS:
            return []
        return [
            {
                "provider_id": "oa2-google-oauth2-1",
                "name": "Google",
                "remote_id": "{}@gmail.com".format(username),
            },
            {
                "provider_id": PROVIDER_ID_TESTSHIB,
                "name": "TestShib",
                # The "testshib:" prefix is stored in the UserSocialAuth.uid field but should
                # not be present in the 'remote_id', since that's an implementation detail:
                "remote_id": 'remote_' + username,
            },
        ]

    @ddt.data(
        # Any user can query their own list of providers
        (ALICE_USERNAME, ALICE_USERNAME, 200),
        (CARL_USERNAME, CARL_USERNAME, 200),
        # A regular user cannot query another user nor deduce the existence of users based on the status code
        (ALICE_USERNAME, STAFF_USERNAME, 403),
        (ALICE_USERNAME, "nonexistent_user", 403),
        # Even Staff cannot query other users
        (STAFF_USERNAME, ALICE_USERNAME, 403),
        # But admins can
        (ADMIN_USERNAME, ALICE_USERNAME, 200),
        (ADMIN_USERNAME, CARL_USERNAME, 200),
        (ADMIN_USERNAME, "invalid_username", 404),
    )
    @ddt.unpack
    def test_list_connected_providers(self, request_user, target_user, expect_result):
        self.client.login(username=request_user, password=PASSWORD)
        url = self.make_url({'username': target_user})

        response = self.client.get(url)
        self.assertEqual(response.status_code, expect_result)
        if expect_result == 200:
            self.assertIn("active", response.data)
            self.assertItemsEqual(response.data["active"], self.expected_active(target_user))

    @ddt.data(
        # A server with a valid API key can query any user's list of providers
        (VALID_API_KEY, ALICE_USERNAME, 200),
        (VALID_API_KEY, "invalid_username", 404),
        ("i am an invalid key", ALICE_USERNAME, 403),
        (None, ALICE_USERNAME, 403),
    )
    @ddt.unpack
    def test_list_connected_providers_with_api_key(self, api_key, target_user, expect_result):
        url = self.make_url({'username': target_user})
        response = self.client.get(url, HTTP_X_EDX_API_KEY=api_key)
        self.assertEqual(response.status_code, expect_result)
        if expect_result == 200:
            self.assertIn("active", response.data)
            self.assertItemsEqual(response.data["active"], self.expected_active(target_user))

    @ddt.data(
        (True, ALICE_USERNAME, 200, True),
        (True, CARL_USERNAME, 200, False),
        (False, ALICE_USERNAME, 200, True),
        (False, CARL_USERNAME, 403, None),
    )
    @ddt.unpack
    def test_allow_unprivileged_response(self, allow_unprivileged, requesting_user, expect, include_remote_id):
        self.client.login(username=requesting_user, password=PASSWORD)
        with override_settings(ALLOW_UNPRIVILEGED_SSO_PROVIDER_QUERY=allow_unprivileged):
            url = self.make_url({'username': ALICE_USERNAME})
            response = self.client.get(url)
        self.assertEqual(response.status_code, expect)
        if response.status_code == 200:
            self.assertGreater(len(response.data['active']), 0)
            for provider_data in response.data['active']:
                self.assertEqual(include_remote_id, 'remote_id' in provider_data)

    def test_allow_query_by_email(self):
        self.client.login(username=ALICE_USERNAME, password=PASSWORD)
        url = self.make_url({'email': '{}@example.com'.format(ALICE_USERNAME)})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.data['active']), 0)

    def test_throttling(self):
        # Default throttle is 10/min.  Make 11 requests to verify
        throttling_user = UserFactory.create(password=PASSWORD)
        self.client.login(username=throttling_user.username, password=PASSWORD)
        url = self.make_url({'username': ALICE_USERNAME})
        with override_settings(ALLOW_UNPRIVILEGED_SSO_PROVIDER_QUERY=True):
            for _ in range(10):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)


@override_settings(EDX_API_KEY=VALID_API_KEY)
@ddt.ddt
@unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
class UserViewAPITests(UserViewsMixin, TpaAPITestCase):
    """
    Test the Third Party Auth User REST API
    """

    def make_url(self, identifier):
        """
        Return the view URL, with the identifier provided
        """
        return reverse(
            'third_party_auth_users_api',
            kwargs={'username': identifier.values()[0]}
        )


@override_settings(EDX_API_KEY=VALID_API_KEY)
@ddt.ddt
@unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
class UserViewV2APITests(UserViewsMixin, TpaAPITestCase):
    """
    Test the Third Party Auth User REST API
    """

    def make_url(self, identifier):
        """
        Return the view URL, with the identifier provided
        """
        return '?'.join([
            reverse('third_party_auth_users_api_v2'),
            six.moves.urllib.parse.urlencode(identifier)
        ])


@override_settings(EDX_API_KEY=VALID_API_KEY)
@ddt.ddt
@unittest.skipUnless(settings.ROOT_URLCONF == 'lms.urls', 'Test only valid in lms')
class UserMappingViewAPITests(TpaAPITestCase):
    """
    Test the Third Party Auth User Mapping REST API
    """
    @ddt.data(
        (VALID_API_KEY, PROVIDER_ID_TESTSHIB, 200, get_mapping_data_by_usernames(LINKED_USERS)),
        ("i am an invalid key", PROVIDER_ID_TESTSHIB, 403, None),
        (None, PROVIDER_ID_TESTSHIB, 403, None),
        (VALID_API_KEY, 'non-existing-id', 404, []),
    )
    @ddt.unpack
    def test_list_all_user_mappings_withapi_key(self, api_key, provider_id, expect_code, expect_data):
        url = reverse('third_party_auth_user_mapping_api', kwargs={'provider_id': provider_id})
        response = self.client.get(url, HTTP_X_EDX_API_KEY=api_key)
        self._verify_response(response, expect_code, expect_data)

    @ddt.data(
        (PROVIDER_ID_TESTSHIB, 'valid-token', 200, get_mapping_data_by_usernames(LINKED_USERS)),
        ('non-existing-id', 'valid-token', 404, []),
        (PROVIDER_ID_TESTSHIB, 'invalid-token', 401, []),
    )
    @ddt.unpack
    def test_list_all_user_mappings_oauth2(self, provider_id, access_token, expect_code, expect_data):
        url = reverse('third_party_auth_user_mapping_api', kwargs={'provider_id': provider_id})
        # create oauth2 auth data
        user = UserFactory.create(username='api_user')
        client = Client.objects.create(name='oauth2_client', client_type=CONFIDENTIAL)
        token = AccessToken.objects.create(user=user, client=client)
        ProviderApiPermissions.objects.create(client=client, provider_id=provider_id)

        if access_token == 'valid-token':
            access_token = token.token

        response = self.client.get(url, HTTP_AUTHORIZATION='Bearer {}'.format(access_token))
        self._verify_response(response, expect_code, expect_data)

    @ddt.data(
        ({'username': [ALICE_USERNAME, STAFF_USERNAME]}, 200,
         get_mapping_data_by_usernames([ALICE_USERNAME, STAFF_USERNAME])),
        ({'remote_id': ['remote_' + ALICE_USERNAME, 'remote_' + STAFF_USERNAME, 'remote_' + CARL_USERNAME]}, 200,
         get_mapping_data_by_usernames([ALICE_USERNAME, STAFF_USERNAME])),
        ({'username': [ALICE_USERNAME, CARL_USERNAME, STAFF_USERNAME]}, 200,
         get_mapping_data_by_usernames([ALICE_USERNAME, STAFF_USERNAME])),
        ({'username': [ALICE_USERNAME], 'remote_id': ['remote_' + STAFF_USERNAME]}, 200,
         get_mapping_data_by_usernames([ALICE_USERNAME, STAFF_USERNAME])),
    )
    @ddt.unpack
    def test_user_mappings_with_query_params_comma_separated(self, query_params, expect_code, expect_data):
        """ test queries like username=user1,user2,... """
        base_url = reverse(
            'third_party_auth_user_mapping_api', kwargs={'provider_id': PROVIDER_ID_TESTSHIB}
        )
        params = []
        for attr in ['username', 'remote_id']:
            if attr in query_params:
                params.append('{}={}'.format(attr, ','.join(query_params[attr])))
        url = "{}?{}".format(base_url, '&'.join(params))
        response = self.client.get(url, HTTP_X_EDX_API_KEY=VALID_API_KEY)
        self._verify_response(response, expect_code, expect_data)

    @ddt.data(
        ({'username': [ALICE_USERNAME, STAFF_USERNAME]}, 200,
         get_mapping_data_by_usernames([ALICE_USERNAME, STAFF_USERNAME])),
        ({'remote_id': ['remote_' + ALICE_USERNAME, 'remote_' + STAFF_USERNAME, 'remote_' + CARL_USERNAME]}, 200,
         get_mapping_data_by_usernames([ALICE_USERNAME, STAFF_USERNAME])),
        ({'username': [ALICE_USERNAME, CARL_USERNAME, STAFF_USERNAME]}, 200,
         get_mapping_data_by_usernames([ALICE_USERNAME, STAFF_USERNAME])),
        ({'username': [ALICE_USERNAME], 'remote_id': ['remote_' + STAFF_USERNAME]}, 200,
         get_mapping_data_by_usernames([ALICE_USERNAME, STAFF_USERNAME])),
    )
    @ddt.unpack
    def test_user_mappings_with_query_params_multi_value_key(self, query_params, expect_code, expect_data):
        """ test queries like username=user1&username=user2&... """
        base_url = reverse(
            'third_party_auth_user_mapping_api', kwargs={'provider_id': PROVIDER_ID_TESTSHIB}
        )
        params = QueryDict('', mutable=True)
        for attr in ['username', 'remote_id']:
            if attr in query_params:
                params.setlist(attr, query_params[attr])
        url = "{}?{}".format(base_url, params.urlencode())
        response = self.client.get(url, HTTP_X_EDX_API_KEY=VALID_API_KEY)
        self._verify_response(response, expect_code, expect_data)

    def test_user_mappings_only_return_requested_idp_mapping_by_provider_id(self):
        testshib2 = self.configure_saml_provider(name='TestShib2', enabled=True, slug='testshib2')
        username = 'testshib2user'
        user = UserFactory.create(
            username=username,
            password=PASSWORD,
            is_staff=False,
            is_superuser=False
        )
        UserSocialAuth.objects.create(
            user=user,
            provider=testshib2.backend_name,
            uid='{}:{}'.format(testshib2.slug, username),
        )

        url = reverse('third_party_auth_user_mapping_api', kwargs={'provider_id': PROVIDER_ID_TESTSHIB})
        response = self.client.get(url, HTTP_X_EDX_API_KEY=VALID_API_KEY)
        self.assertEqual(response.status_code, 200)
        self._verify_response(response, 200, get_mapping_data_by_usernames(LINKED_USERS))

    @ddt.data(
        (True, True, 200),
        (False, True, 200),
        (True, False, 200),
        (False, False, 403)
    )
    @ddt.unpack
    def test_user_mapping_permission_logic(self, api_key_permission, token_permission, expect):
        url = reverse('third_party_auth_user_mapping_api', kwargs={'provider_id': PROVIDER_ID_TESTSHIB})
        with patch.object(ApiKeyHeaderPermission, 'has_permission', return_value=api_key_permission):
            with patch.object(ThirdPartyAuthProviderApiPermission, 'has_permission', return_value=token_permission):
                response = self.client.get(url)
                self.assertEqual(response.status_code, expect)

    def _verify_response(self, response, expect_code, expect_result):
        """ verify the items in data_list exists in response and data_results matches results in response """
        self.assertEqual(response.status_code, expect_code)
        if expect_code == 200:
            for item in ['results', 'count', 'num_pages']:
                self.assertIn(item, response.data)
            self.assertItemsEqual(response.data['results'], expect_result)


class TestOAuth2ProviderViewset(ThirdPartyAuthTestMixin, APITestCase):
    @classmethod
    def setUpClass(cls):
        super(TestOAuth2ProviderViewset, cls).setUpClass()
        cls.non_admin_user = UserFactory()
        cls.admin_user = UserFactory(is_superuser=True)

    def _get_url(self, name, backend='keycloak', pk=None):
        """Return the URL for the given viewset name"""
        if name == 'list' or name == 'create':
            return reverse('third_party_auth_oauth_providers-list',
                           kwargs={'backend': backend})
        if name == 'detail' or name == 'delete' or name == 'update':
            return reverse('third_party_auth_oauth_providers-detail',
                           kwargs={'pk': pk, 'backend': backend})

    def test_missing_auth_token_fails(self):
        """401 returned for all endpoints if no OAuth info provided"""
        # GET list
        resp = self.client.get(self._get_url('list'))
        assert resp.status_code == 401

        resp = self.client.get(self._get_url('detail', pk=1))
        assert resp.status_code == 401

        resp = self.client.post(self._get_url('list'), data={})
        assert resp.status_code == 401

    @pytest.mark.skip("Figure out how to test non-admin-fails")
    def test_non_admin_access_fails(self):
        """Providers for specified backend are only ones returned"""
        self.client.force_authenticate(user=self.non_admin_user)
        resp = self.client.get(self._get_url('list'))
        assert resp.status_code == 401

    def test_only_providers_for_specified_backend_returned(self):
        """Providers for specified backend are only ones returned"""
        self.client.force_authenticate(user=self.admin_user)

        # Google and keycloak provider exist
        self.configure_google_provider()
        self.configure_keycloak_provider()

        # One item returned for google-oauth2
        resp = self.client.get(self._get_url('list', backend='google-oauth2'))
        assert len(resp.json()) == 1

        # One item returned for keycloak
        resp = self.client.get(self._get_url('list'))
        assert len(resp.json()) == 1

        # No items returned for a backend that has no entries
        resp = self.client.get(self._get_url('list', backend='facebook'))
        assert len(resp.json()) == 0

    def test_delete_not_supported(self):
        """Attempt to DELETE pk returns 405 not supported"""
        self.client.force_authenticate(user=self.admin_user)
        provider = self.configure_keycloak_provider()
        resp = self.client.delete(self._get_url('delete', pk=provider.id))
        assert resp.status_code == 405

    def test_put_not_supported(self):
        """Attempt to PUT to pk returns 405 not supported"""
        self.client.force_authenticate(user=self.admin_user)
        provider = self.configure_keycloak_provider()
        resp = self.client.put(self._get_url('update', pk=provider.id))
        assert resp.status_code == 405

    def test_patch_not_supported(self):
        """Attempt to PATCH to pk returns 405 not supported"""
        self.client.force_authenticate(user=self.admin_user)
        provider = self.configure_keycloak_provider()
        resp = self.client.patch(self._get_url('update', pk=provider.id))
        assert resp.status_code == 405

    def test_detail_endpoint_returns_proper_contents(self):
        """Test detail returns proper contents"""
        self.client.force_authenticate(user=self.admin_user)

        other_settings = {
            u'PUBLIC_KEY': u'some-public-key',
            u'AUTHORIZATION_URL': u'https://auth.url.com',
            u'ACCESS_TOKEN_URL': u'https://access.token.url.com'
        }

        provider_args = {
            'name': 'Org 1',
            'key': 'edx',
            'other_settings': json.dumps(other_settings),
            'enabled': True,
            'changed_by': self.admin_user,
            'change_date': '2019-01-01T10:00:00.000000Z'
        }
        provider = self.configure_keycloak_provider(**provider_args)

        expected = {
            'id': 1,
            'name': 'Org 1',
            'client_id': 'edx',
            'secret': 'opensesame',
            'changed_by': self.admin_user.username,
            'other_settings': other_settings,
            'enabled': True,
            'site': 'example.com'
        }
        resp = self.client.get(self._get_url('detail', pk=provider.id))
        resp_data = resp.json()
        assert 'change_date' in resp_data
        # auto set to when it was updated so can't really check exact value
        resp_data.pop('change_date')
        assert resp_data == expected

    def test_detail_returns_404_if_wrong_backend_specified(self):
        """Detail returns 404 if pk is not for value in specified backend"""
        self.client.force_authenticate(user=self.admin_user)
        kc = self.configure_keycloak_provider()
        google = self.configure_google_provider()

        # using keycloak backend but specififying pk of google returns 404
        resp = self.client.get(self._get_url(
            'detail', backend='keycloak', pk=google.id))
        assert resp.status_code == 404

        # using keycloack backend and specifying pk of keycloak returns 200
        resp = self.client.get(self._get_url(
            'detail', backend='keycloak', pk=kc.id))
        assert resp.status_code == 200

    def test_post_creates_new_config_for_new_site(self):
        """POST creates new entry for same backend but different site"""
        self.client.force_authenticate(user=self.admin_user)
        new_site = SiteFactory()

        # Starts with only one provider in current set after creating one
        provider = self.configure_keycloak_provider()
        assert OAuth2ProviderConfig.objects.current_set().count() == 1

        other_settings = {
            u'PUBLIC_KEY': u'some-public-key',
            u'AUTHORIZATION_URL': u'https://auth.url.com',
            u'ACCESS_TOKEN_URL': u'https://access.token.url.com'
        }
        payload = {
            'name': 'Org 1',
            'client_id': 'edx',
            'secret': 'new-secret',
            'other_settings': other_settings,
            'enabled': True,
            'site': new_site.domain,
        }

        resp = self.client.post(self._get_url('list'), data=payload, format='json')

        expected = copy.deepcopy(payload)
        expected['changed_by'] = self.admin_user.username
        expected['id'] = 2

        data = resp.json()
        # Change date automatically updated, check for presence only
        assert 'change_date' in data
        data.pop('change_date')

        assert data == expected

        # Should now be 2 entries in current set, one for each site
        configs = OAuth2ProviderConfig.objects.current_set()
        assert configs.count() == 2
        assert configs.filter(site=new_site, backend_name='keycloak').count() == 1
        assert configs.filter(site=provider.site, backend_name='keycloak').count() == 1

    def test_post_replaces_current_config_for_same_backend_and_site(self):
        """POST creates new config that becomes current for same backend/site"""
        self.client.force_authenticate(user=self.admin_user)

        # Starts with only one provider in current set after creating one
        provider = self.configure_keycloak_provider()
        assert OAuth2ProviderConfig.objects.current_set().count() == 1

        other_settings = {
            u'PUBLIC_KEY': u'some-public-key',
            u'AUTHORIZATION_URL': u'https://auth.url.com',
            u'ACCESS_TOKEN_URL': u'https://access.token.url.com'
        }
        payload = {
            'name': 'New Name',
            'client_id': 'edx',
            'secret': 'new-secret',
            'other_settings': other_settings,
            'enabled': False,
            'site': provider.site.domain
        }

        resp = self.client.post(self._get_url('list'), data=payload, format='json')

        expected = copy.deepcopy(payload)
        expected['changed_by'] = self.admin_user.username
        expected['id'] = 2

        data = resp.json()
        # Change date automatically updated, check for presence only
        assert 'change_date' in data
        data.pop('change_date')

        assert data == expected

        # Will still only be 1 config in current_set
        configs = OAuth2ProviderConfig.objects.current_set()
        assert configs.count() == 1

        # and it will be the one returned by our POST
        assert configs[0].id == 2
