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

TPA_LOGOUT_PROVIDER = getattr(settings, 'TPA_LOGOUT_PROVIDER', None)
TPA_POST_LOGOUT_REDIRECT_FIELD = getattr(settings, 'TPA_POST_LOGOUT_REDIRECT_FIELD', 'redirect_uri')
TPA_POST_LOGOUT_REDIRECT_URL = getattr(settings, 'TPA_POST_LOGOUT_REDIRECT_URL', 'current_site')


class TPALogoutView(LogoutView):
    """Set post redirect target to end session url of TPA_LOGOUT_PROVIDER

    This only occurs if this setting is filled out. If there is an
    END_SESSION_URL value in the TPA_LOGOUT_PROVIDER backend's other settings,
    it will redirect to that endpoint after logging the user out.

    Ideally, that endpoint will redirect the user back to the the current
    domains home page.
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
            # for the CMS,
            context = self.get_context_data()
            target = context.get('target')
            if not target:
                log.error("Missing target; falling back to original response")
                response = self._get_original_response(request, *args, **kwargs)
            else:
                response = redirect(target)

        # Clear the cookie used by the edx.org marketing site
        delete_logged_in_cookies(response)

        return response

    def _get_original_response(self, request, *args, **kwargs):
        """Return the response based on the original function"""
        if settings.FEATURES.get('DISABLE_STUDIO_SSO_OVER_LMS', False) and not self.oauth_client_ids:
            response = redirect(self.target)
        else:
            response = super(LogoutView, self).dispatch(request, *args, **kwargs)
        return response

    def get_context_data(self, **kwargs):
        context = super(TPALogoutView, self).get_context_data(**kwargs)
        # Default behavior if not logoout provider set
        if TPA_LOGOUT_PROVIDER is None or not self.tpa_logout_url:
            return context

        end_session_url = self._add_post_logout_redirect_uri(self.tpa_logout_url)
        context['target'] = end_session_url
        return context

    def _get_end_session_url(self, backend):
        """Return end_session_url or '' if not set on backend"""
        try:
            end_session_url = backend.get_setting('END_SESSION_URL')
        except KeyError:
            end_session_url = ""
        return end_session_url

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
