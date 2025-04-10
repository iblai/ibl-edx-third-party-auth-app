"""
Extra views required for SSO
"""

import uuid
import logging

from django.views.decorators.csrf import csrf_exempt

from ibl_third_party_auth import backchannel_logout
from django.contrib.auth import get_user_model
from django.http.response import JsonResponse
from oauth2_provider.models import get_application_model, Application
from django.views.decorators.http import require_http_methods

log = logging.getLogger(__name__)


@csrf_exempt
def back_channel_logout(request, backend):
    """Back Channel logout"""
    return backchannel_logout.back_channel_logout(request, backend)



@require_http_methods(["POST"])
def oauth_dynamic_client_registration(request):
    user, _ = get_user_model().objects.get_or_create(username="ibltokenmanager")
    client_metadata = request.POST
    client = get_application_model().objects.create(
        user_id=user.id,
        redirect_uris=" ".join(client_metadata.get("redirect_uris", [])),
        post_logout_redirect_uris="",
        authorization_grant_type=client_metadata.get("grant_types", ["authorization_code"])[0].replace("_", "-"),
        name=f"dynamic-registration-{uuid.uuid4().hex}",
        client_type=client_metadata.get("client_type", Application.CLIENT_PUBLIC),
    )
    return JsonResponse({"client_id": client.client_id,
                     "client_secret": client.client_secret, 
                         "redirect_uris": client.redirect_uris.split()})
