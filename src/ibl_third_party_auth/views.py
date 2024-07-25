"""
Extra views required for SSO
"""

import logging

from django.views.decorators.csrf import csrf_exempt

from ibl_third_party_auth import backchannel_logout

log = logging.getLogger(__name__)


@csrf_exempt
def back_channel_logout(request, backend):
    """Back Channel logout"""
    return backchannel_logout.back_channel_logout(request, backend)
