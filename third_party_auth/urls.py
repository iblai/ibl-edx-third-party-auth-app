"""Url configuration for the auth module."""

from django.conf import settings
from django.conf.urls import include, url

from .views import (
    inactive_user_view, lti_login_and_complete_view, post_to_custom_auth_form, saml_metadata_view,
    TPALogoutView
)

urlpatterns = [
    url(r'^auth/inactive', inactive_user_view, name="third_party_inactive_redirect"),
    url(r'^auth/custom_auth_entry', post_to_custom_auth_form, name='tpa_post_to_custom_auth_form'),
    url(r'^auth/saml/metadata.xml', saml_metadata_view),
    url(r'^auth/login/(?P<backend>lti)/$', lti_login_and_complete_view),
    url(r'^auth/', include('social_django.urls', namespace='social')),
]

# Override logout view to redirect user to end session endpoint of
# provider listed in TPA_LOGOUT_PROVIDER
if getattr(settings, 'TPA_LOGOUT_PROVIDER', None):
    urlpatterns += [url(r'logout', TPALogoutView.as_view(), name='logout')]

# https://openid.net/specs/openid-connect-session-1_0.html#RPiframe
if getattr(settings, 'TPA_ENABLE_OP_SESSION_MANAGEMENT', False):
    urlpatterns += [
        url(r'^auth/', include('third_party_auth.session_urls'))
    ]
