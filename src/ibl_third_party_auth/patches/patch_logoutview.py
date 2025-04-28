import logging
from urllib.parse import urlencode

from common.djangoapps.third_party_auth import pipeline as tpa_pipeline
from django.conf import settings
from django.contrib.auth import logout
from django.shortcuts import redirect
from openedx.core.djangoapps.safe_sessions.middleware import (
    mark_user_change_as_expected,
)
from openedx.core.djangoapps.user_authn.cookies import delete_logged_in_cookies
from openedx.core.djangoapps.user_authn.views import logout as logout_views
from openedx.core.djangoapps.user_authn.views.logout import LogoutView

log = logging.getLogger(__name__)

TPA_POST_LOGOUT_REDIRECT_FIELD = getattr(
    settings, "TPA_POST_LOGOUT_REDIRECT_FIELD", "redirect_uri"
)
TPA_POST_LOGOUT_REDIRECT_URL = getattr(
    settings, "TPA_POST_LOGOUT_REDIRECT_URL", "current_site"
)


def dispatch(self, request, *args, **kwargs):
    self.tpa_logout_url = tpa_pipeline.get_idp_logout_url_from_running_pipeline(request)

    logout(request)
    # Start IBL Patch
    if settings.ROOT_URLCONF.startswith("lms"):
        # For the LMS, we redirect to the normal logout page
        response = super(LogoutView, self).dispatch(request, *args, **kwargs)
    else:
        # CMS can't use the normal logout template b/c template exists in LMS
        # So we return a redirect to target after logging out
        context = self.get_context_data()
        target = context.get("target")
        response = redirect(target)
    # End IBL Patch

    # Clear the cookie used by the edx.org marketing site
    delete_logged_in_cookies(response)

    mark_user_change_as_expected(None)
    return response


def get_context_data(self, **kwargs):
    # IBL PATCH STARTS
    """Add redirect_url to tpa_logout_url if it exists"""
    context = self.orig_get_context_data(**kwargs)
    # Default behavior if no logout_url
    if not self.tpa_logout_url:
        return context

    end_session_url = self._add_post_logout_redirect_uri(self.tpa_logout_url)
    context["target"] = end_session_url
    # IBL PATCH ENDS
    return context


# IBL PATCH STARTS
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

    if TPA_POST_LOGOUT_REDIRECT_URL == "current_site":
        protocol = "https" if self.request.is_secure() else "http"
        url = "{}://{}".format(protocol, self.request.site.domain)
    else:
        url = TPA_POST_LOGOUT_REDIRECT_URL

    redirect_uri = {TPA_POST_LOGOUT_REDIRECT_FIELD: url}
    query_string = urlencode(redirect_uri)
    end_session_url += "?{}".format(query_string)
    return end_session_url


# IBL PATCH ENDS


def patch():
    # Preserve original functions
    logout_views.LogoutView.orig_get_context_data = (
        logout_views.LogoutView.get_context_data
    )

    # Patch
    logout_views.LogoutView.dispatch = dispatch
    logout_views.LogoutView.get_context_data = get_context_data
    logout_views.LogoutView._add_post_logout_redirect_uri = (
        _add_post_logout_redirect_uri
    )
