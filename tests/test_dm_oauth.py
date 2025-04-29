from ibl_request_router.config import (
    MANAGER_TOKEN_ENDPOINT_PATH,
)
from django.test import TestCase, Client
from . import factories
import requests_mock
import pytest
from django.urls import reverse


@pytest.mark.django_db
class DMOAuthTest(TestCase):
    @classmethod
    def setUpClass(cls):
        super(DMOAuthTest, cls).setUpClass()
        cls.client = Client()
    @requests_mock.Mocker()
    def test_can_get_dm_token_from_token_endpoint(self, m):
        m.post(MANAGER_TOKEN_ENDPOINT_PATH, json=factories.DMTokenResponseFactory(),)

        grant = factories.GrantFactory()
        post_data = {
            'grant_type': 'authorization_code',
            'code': grant.code,
            'client_id': grant.application.client_id,
            'client_secret': grant.application.client_secret, 
            'redirect_uri': grant.redirect_uri,
        }
        response = self.client.post(reverse("ibl-oauth-dmtoken"), data=post_data)
        resp_json = response.json()
        assert response.status_code == 200
        assert isinstance(resp_json["access_token"], str)
        assert bool(resp_json["access_token"])
        assert resp_json["token_type"] == "Token"
        assert isinstance(resp_json["expires_in"], int)
        assert resp_json["expires_in"] > 0
        assert "refresh_token" in resp_json
        assert isinstance(resp_json["scope"], str)
        assert bool(resp_json["scope"])

    def test_can_dynamic_register_application(self):
        redirect_uris=  ["http://localhost:3000"]
        response = self.client.post(
            reverse("ibl-oauth-dcr"), 
            data={"redirect_uris": redirect_uris},
            content_type="application/json",
        )
        assert response.status_code == 200
        assert response.json()["client_id"]
        assert response.json()["client_secret"]
        assert response.json()["redirect_uris"] == redirect_uris