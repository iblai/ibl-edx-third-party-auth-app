import json
from unittest import mock

import pytest
from django.urls import reverse
from ibl_request_router.config import MANAGER_BASE_API_URL, MANAGER_TOKEN_ENDPOINT_PATH
from rest_framework.test import APIClient

from . import factories

MANAGER_URL = "http://manager.base.local"


@pytest.fixture(autouse=True)
def set_manager_url():
    with mock.patch("ibl_request_router.api.manager.MANAGER_BASE_URL", MANAGER_URL):
        with mock.patch(
            "ibl_request_router.api.manager.MANAGER_BASE_API_URL",
            f"{MANAGER_URL}/api",
        ):
            yield


@pytest.fixture
def dm_token_resp(requests_mock):
    """Configure a DM token response"""

    def _inner(json_data=None, status_code=200, exc=None):
        data = (
            {} if json_data == {} else json_data or factories.DMTokenResponseFactory()
        )
        kwargs = {"exc": exc} if exc else {"json": data, "status_code": status_code}
        requests_mock.post(
            "{}/{}".format(
                MANAGER_BASE_API_URL, MANAGER_TOKEN_ENDPOINT_PATH.lstrip("/")
            ),
            **kwargs,
        )

    return _inner


@pytest.mark.django_db
class TestDMOAuth:
    @pytest.fixture(autouse=True)
    def setup(self, dm_token_resp):
        self.client = APIClient()
        self.setup_dm_token_response = dm_token_resp

    def test_can_get_dm_token_from_token_endpoint(self):
        self.setup_dm_token_response()

        grant = factories.GrantFactory()
        post_data = {
            "grant_type": "authorization_code",
            "code": grant.code,
            "client_id": grant.application.client_id,
            "client_secret": grant.application.client_secret,
            "redirect_uri": grant.redirect_uri,
        }
        response = self.client.post(
            reverse("ibl_third_party_auth:ibl-oauth-dmtoken"), data=post_data
        )
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
        redirect_uris = ["http://localhost:3000"]
        response = self.client.post(
            reverse("ibl_third_party_auth:ibl-oauth-dcr"),
            data=json.dumps({"redirect_uris": redirect_uris}),
            content_type="application/json",
        )
        assert response.status_code == 200
        assert response.json()["client_id"]
        assert response.json()["client_secret"]
        assert response.json()["redirect_uris"] == redirect_uris
