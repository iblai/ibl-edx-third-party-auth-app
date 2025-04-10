"""
Extra views required for SSO
"""

from oauthlib.oauth2 import Server as OAuth2Server
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.oauth2_backends import OAuthLibCore
import uuid
import json
import logging

from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from ibl_third_party_auth import backchannel_logout
from django.contrib.auth import get_user_model
from django.http.response import JsonResponse
from oauth2_provider.models import get_application_model, Application
from django.views.decorators.http import require_http_methods
from ibl_request_router.api.manager import manager_api_request
from ibl_request_router.config import (
    MANAGER_TOKEN_ENDPOINT_PATH,
)
from django.utils import timezone
from oauth2_provider.views.mixins import OAuthLibMixin
from django.http import Http404
from oauth2_provider.models import get_access_token_model
import hashlib
from django.utils.decorators import method_decorator
import datetime

log = logging.getLogger(__name__)


@csrf_exempt
def back_channel_logout(request, backend):
    """Back Channel logout"""
    return backchannel_logout.back_channel_logout(request, backend)





@method_decorator(csrf_exempt, name='dispatch')
class DMTokenView(OAuthLibMixin, View):
    server_class = OAuth2Server
    validator_class = OAuth2Validator

    oauthlib_backend_class = OAuthLibCore

    @staticmethod
    def parse_iso8601_to_utc(iso_string: str) -> datetime.datetime:
        """
        Parses an ISO 8601 formatted string into a timezone-aware UTC datetime object.
    
        - If the string contains timezone information (e.g., +02:00, -05:00, Z),
          it's converted to UTC.
        - If the string does *not* contain timezone information (naive datetime),
          it's assumed to represent a UTC time, and UTC timezone info is attached.
    
        Args:
            iso_string: The string formatted according to ISO 8601.
    
        Returns:
            A timezone-aware datetime object representing the time in UTC.
    
        Raises:
            ValueError: If the string is not a valid ISO 8601 format
                        parsable by datetime.fromisoformat.
        """
        # Python < 3.11 doesn't handle 'Z' directly in fromisoformat
        # We replace 'Z' with '+00:00' for compatibility
        if iso_string.endswith('Z'):
            iso_string = iso_string[:-1] + '+00:00'
        try:
            dt = datetime.datetime.fromisoformat(iso_string)
            if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
                dt_utc = dt.replace(tzinfo=datetime.timezone.utc)
            else:
                dt_utc = dt.astimezone(datetime.timezone.utc)
            return dt_utc
    
        except ValueError as e:
            raise ValueError(f"Invalid ISO 8601 string format: '{iso_string}'") from e

    def post(self, request, *args, **kwargs):
        url, headers, body, status = self.create_token_response(request)
        if status == 200:
            access_token = json.loads(body).get("access_token")
            token_checksum = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
            token = get_access_token_model().objects.get(token_checksum=token_checksum)
            try:
                response = manager_api_request(
                    "POST", MANAGER_TOKEN_ENDPOINT_PATH, data={"user_id": token.user.id}
                )

                try:
                    data = response.json()
                except ValueError:
                    if response.ok:
                        # Only log when the response is expected to be valid
                        log.exception(
                            "Non-JSON token proxy response: %s %s",
                            response.status_code,
                            response.text,
                        )

                data = None
            except Exception:
                log.exception("Token proxy request error")
                data = None
            if data and not data.get("token"):
                data = None
            if not data:
                raise Http404
            expires_in = None
            if data.get("expiry"):
                expiry = self.parse_iso8601_to_utc(data["expiry"])
                expires_in = (timezone.now() - expiry).total_seconds()

            http_resp_data = {
            "access_token": data["token"],
            "token_type": "Bearer",
            "expires_in": expires_in,
            "refresh_token": None,
            "scope": "read write"
            }

            http_resp = JsonResponse(data=http_resp_data)

            for k, v in headers.items():
                http_resp[k] = v
            return http_resp
        raise Http404

@csrf_exempt
@require_http_methods(["POST"])
def oauth_dynamic_client_registration(request):

    user_model = get_user_model()
    try:
        user = user_model.objects.get(username="ibltokenmanager")
    except user_model.DoesNotExist:
        user = user_model.objects.create(username="ibltokenmanager", email=f"{uuid.uuid4().hex}@ibl.ai")
    client_metadata = json.loads(request.body)
    client = get_application_model().objects.create(
        user_id=user.id,
        redirect_uris=" ".join(client_metadata.get("redirect_uris", [])),
        #post_logout_redirect_uris="",
        authorization_grant_type=client_metadata.get("grant_types", ["authorization_code"])[0].replace("_", "-"),
        name=f"dynamic-registration-{uuid.uuid4().hex}",
        client_type=client_metadata.get("client_type", Application.CLIENT_PUBLIC),
    )
    return JsonResponse({"client_id": client.client_id,
                         "client_secret": client.client_secret, 
                         "redirect_uris": client.redirect_uris.split()})
