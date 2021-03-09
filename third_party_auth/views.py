"""
Extra views required for SSO
"""
import logging
from importlib import import_module

from urllib import urlencode

import edx_oauth2_provider
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import logout
from django.urls import reverse
from django.http import Http404, HttpResponse, HttpResponseNotAllowed, HttpResponseServerError
from django.shortcuts import redirect, render
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt
from social_django.utils import load_strategy, load_backend, psa
from social_django.views import complete
from social_core.utils import setting_name
from social_django.models import UserSocialAuth

from openedx.core.djangoapps.user_authn.views.logout import LogoutView
from openedx.core.djangoapps.user_authn.cookies import delete_logged_in_cookies

from student.models import UserProfile
from student.views import compose_and_send_activation_email

import third_party_auth
from third_party_auth import pipeline, provider, jwt_validation, backchannel_logout

from .models import SAMLConfiguration, SAMLProviderConfig

log = logging.getLogger(__name__)

URL_NAMESPACE = getattr(settings, setting_name('URL_NAMESPACE'), None) or 'social'
TPA_LOGOUT_PROVIDER = getattr(settings, 'TPA_LOGOUT_PROVIDER', None)
TPA_POST_LOGOUT_REDIRECT_FIELD = getattr(settings, 'TPA_POST_LOGOUT_REDIRECT_FIELD', 'redirect_uri')
TPA_POST_LOGOUT_REDIRECT_URL = getattr(settings, 'TPA_POST_LOGOUT_REDIRECT_URL', 'current_site')
SESSIONS_ENGINE = import_module(settings.SESSION_ENGINE)


def inactive_user_view(request):
    """
    A newly or recently registered user has completed the social auth pipeline.
    Their account is not yet activated, but we let them login since the third party auth
    provider is trusted to vouch for them. See details in pipeline.py.

    The reason this view exists is that if we don't define this as the
    SOCIAL_AUTH_INACTIVE_USER_URL, inactive users will get sent to LOGIN_ERROR_URL, which we
    don't want.

    If the third_party_provider.skip_email_verification is set then the user is activated
    and verification email is not sent
    """
    # 'next' may be set to '/account/finish_auth/.../' if this user needs to be auto-enrolled
    # in a course. Otherwise, just redirect them to the dashboard, which displays a message
    # about activating their account.
    user = request.user
    profile = UserProfile.objects.get(user=user)
    activated = user.is_active
    # If the user is registering via 3rd party auth, track which provider they use
    if third_party_auth.is_enabled() and pipeline.running(request):
        running_pipeline = pipeline.get(request)
        third_party_provider = provider.Registry.get_from_pipeline(running_pipeline)
        if third_party_provider.skip_email_verification and not activated:
            user.is_active = True
            user.save()
            activated = True
    if not activated:
        compose_and_send_activation_email(user, profile)

    return redirect(request.GET.get('next', 'dashboard'))


def saml_metadata_view(request):
    """
    Get the Service Provider metadata for this edx-platform instance.
    You must send this XML to any Shibboleth Identity Provider that you wish to use.
    """
    idp_slug = request.GET.get('tpa_hint', None)
    saml_config = 'default'
    if idp_slug:
        idp = SAMLProviderConfig.current(idp_slug)
        if idp.saml_configuration:
            saml_config = idp.saml_configuration.slug
    if not SAMLConfiguration.is_enabled(request.site, saml_config):
        raise Http404
    complete_url = reverse('social:complete', args=("tpa-saml", ))
    if settings.APPEND_SLASH and not complete_url.endswith('/'):
        complete_url = complete_url + '/'  # Required for consistency
    saml_backend = load_backend(load_strategy(request), "tpa-saml", redirect_uri=complete_url)
    metadata, errors = saml_backend.generate_metadata_xml(idp_slug)

    if not errors:
        return HttpResponse(content=metadata, content_type='text/xml')
    return HttpResponseServerError(content=', '.join(errors))


@csrf_exempt
@psa('{0}:complete'.format(URL_NAMESPACE))
def lti_login_and_complete_view(request, backend, *args, **kwargs):
    """This is a combination login/complete due to LTI being a one step login"""

    if request.method != 'POST':
        return HttpResponseNotAllowed('POST')

    request.backend.start()
    return complete(request, backend, *args, **kwargs)


def post_to_custom_auth_form(request):
    """
    Redirect to a custom login/register page.

    Since we can't do a redirect-to-POST, this view is used to pass SSO data from
    the third_party_auth pipeline to a custom login/register form (possibly on another server).
    """
    pipeline_data = request.session.pop('tpa_custom_auth_entry_data', None)
    if not pipeline_data:
        raise Http404
    # Verify the format of pipeline_data:
    data = {
        'post_url': pipeline_data['post_url'],
        # data: The provider info and user's name, email, etc. as base64 encoded JSON
        # It's base64 encoded because it's signed cryptographically and we don't want whitespace
        # or ordering issues affecting the hash/signature.
        'data': pipeline_data['data'],
        # The cryptographic hash of user_data:
        'hmac': pipeline_data['hmac'],
    }
    return render(request, 'third_party_auth/post_custom_auth_entry.html', data)


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

        # Get the list of authorized clients before we clear the session.
        self.oauth_client_ids = request.session.get(edx_oauth2_provider.constants.AUTHORIZED_CLIENTS_SESSION_KEY, [])

        logout(request)

        if settings.PROJECT_ROOT.name == 'lms':
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
        log.info(context)
        if TPA_LOGOUT_PROVIDER is None:
            return context

        backend = provider.Registry.get_from_pipeline(
            {'backend': TPA_LOGOUT_PROVIDER})

        # Default behavior if specified backend isn't found
        if not backend:
            log.error(
                'Expected backend from TPA_LOGOUT_PROVIDER: %s not found '
                'for site %s; defaulting to normal logout behavior',
                TPA_LOGOUT_PROVIDER, self.request.site.domain)
            return context

        relogin = self.request.GET.get('relogin')

        # Want to log user out and redirect them to their providers login
        # This is used when a user's OP session ends via check-session-iframe
        if relogin is not None:
            login_url = pipeline.get_login_url(
                # TODO: Fix the redirect URL to be more appropriate?
                backend.provider_id,
                'login',
                redirect_url=self.request.GET.get('next', '/'))
            context['target'] = login_url
            return context

        # Use the end session endpoint as the redirect target
        end_session_url = self._get_end_session_url(backend)
        end_session_url = self._add_post_logout_redirect_uri(end_session_url)
        context['target'] = end_session_url if end_session_url else context['target']
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
            url = 'https://{}'.format(self.request.site.domain)
        else:
            url = TPA_POST_LOGOUT_REDIRECT_URL

        redirect_uri = {TPA_POST_LOGOUT_REDIRECT_FIELD: url}
        query_string = urlencode(redirect_uri)
        end_session_url += '?{}'.format(query_string)
        return end_session_url


@xframe_options_exempt
def check_session_rp_iframe(request):
    """Renders the RP session iframe

    https://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification

    We only want to render this check if:
        - user is authenticated
            - don't want non-logged in user to be forced to login
        - user has a session_state in their session
            - this will get populated as part of social auth pipeline if
              OP session management is enabled. If logged in through normal
              django means, this value won't be in the session.
    """
    if TPA_LOGOUT_PROVIDER is None:
        log.error("TPA_ENABLE_OP_SESSION_MANAGEMENT is True, but no "
                  "TPA_LOGOUT_PROVIDER is set")
        return HttpResponse(status=500)

    # Don't want to do any checking if it's an anon user or the user has no
    # session_state (means the didn't login through OIDC provider)
    session_state = request.session.get('session_state')
    if not request.user.is_authenticated() or session_state is None:
        log.debug("Not displaying b/c user not auth'd or no session state")
        return HttpResponse(status=404)

    backend = provider.Registry.get_from_pipeline(
        {'backend': TPA_LOGOUT_PROVIDER})

    if backend is None:
        log.error(
            'Expected backend from TPA_LOGOUT_PROVIDER: %s not found for site %s',
            TPA_LOGOUT_PROVIDER, request.site.domain)
        return HttpResponse(status=500)

    # Get required settings from backend
    try:
        target_op = backend.get_setting('TARGET_OP')
        check_session_url = backend.get_setting('CHECK_SESSION_URL')
        client_id = backend.get_setting('KEY')
    except KeyError as e:
        log.error("Missing backend setting: {}".format(e))
        return HttpResponse(status=500)

    context = {
        'target_op': target_op,
        'check_session_url': check_session_url,
        'client_id': client_id,
        'session_state': session_state,
        'logout_uri': reverse('logout') + '?relogin=1&next=',
    }
    return render(request, 'third_party_auth/check_session_iframe.html', context)


@csrf_exempt
def back_channel_logout(request, backend):
    """Back Channel logout"""
    return backchannel_logout.back_channel_logout(request, backend)