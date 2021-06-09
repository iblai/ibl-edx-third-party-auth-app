"""
Extra views required for SSO
"""

import logging
from importlib import import_module

from urllib.parse import urlencode

from django.contrib.auth import logout
from django.conf import settings
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View
from social_core.utils import setting_name
from social_django.models import UserSocialAuth

from openedx.core.djangoapps.user_authn.views.logout import LogoutView
from openedx.core.djangoapps.user_authn.cookies import delete_logged_in_cookies

from common.djangoapps.third_party_auth import pipeline as tpa_pipeline, provider

from ibl_third_party_auth import backchannel_logout


log = logging.getLogger(__name__)

TPA_POST_LOGOUT_REDIRECT_FIELD = getattr(settings, 'TPA_POST_LOGOUT_REDIRECT_FIELD', 'redirect_uri')
TPA_POST_LOGOUT_REDIRECT_URL = getattr(settings, 'TPA_POST_LOGOUT_REDIRECT_URL', 'current_site')


class TPALogoutView(LogoutView):
    """Set post redirect target to `logout_url` of current IDP

    This only occurs if this setting is filled out. If there is a `logout_url`
    value in the backend's other_settings, it will redirect to that endpoint
    after logging the user out.

    We set the `redirect_uri` of the end session endpoint to point back to
    the current domain, so after ending the session they should be returned
    to the landing page.
    """
    def dispatch(self, request, *args, **kwargs):
        """Changes how response is created"""
        # We do not log here, because we have a handler registered to perform logging on successful logouts.
        request.is_from_logout = True

        # Get third party auth provider's logout url
        self.tpa_logout_url = tpa_pipeline.get_idp_logout_url_from_running_pipeline(request)

        logout(request)

        if settings.ROOT_URLCONF.startswith('lms'):
            # For the LMS, we redirect to the normal logout page
            response = super(LogoutView, self).dispatch(request, *args, **kwargs)
        else:
            # CMS can't use the normal logout template b/c template exists in LMS
            # So we return a redirect to target after logging out
            context = self.get_context_data()
            target = context.get('target')
            response = redirect(target)

        # Clear the cookie used by the edx.org marketing site
        delete_logged_in_cookies(response)

        return response

    def get_context_data(self, **kwargs):
        """Add redirect_url to tpa_logout_url if it exists"""
        context = super(TPALogoutView, self).get_context_data(**kwargs)
        # Default behavior if no logout_url
        if not self.tpa_logout_url:
            return context

        end_session_url = self._add_post_logout_redirect_uri(self.tpa_logout_url)
        context['target'] = end_session_url
        return context

    def _add_post_logout_redirect_uri(self, end_session_url):
        """Optionally add query string for post logout redirect

        Args:
            end_session_url (str): current end session url
        Returns:
            end_session_url or end_session_url + redirect query string

        https://openid.net/specs/openid-connect-session-1_0.html#RedirectionAfterLogout
        """
        if not end_session_url or TPA_POST_LOGOUT_REDIRECT_URL is None:
            return end_session_url

        if TPA_POST_LOGOUT_REDIRECT_URL == 'current_site':
            protocol = 'https' if self.request.is_secure() else 'http'
            url = '{}://{}'.format(protocol, self.request.site.domain)
        else:
            url = TPA_POST_LOGOUT_REDIRECT_URL

        redirect_uri = {TPA_POST_LOGOUT_REDIRECT_FIELD: url}
        query_string = urlencode(redirect_uri)
        end_session_url += '?{}'.format(query_string)
        return end_session_url


@csrf_exempt
def back_channel_logout(request, backend):
    """Back Channel logout"""
    return backchannel_logout.back_channel_logout(request, backend)
