"""Url configuration for the auth module."""

from django.urls import path

from .api import urls as api_urls
from .registration import IblUserManagementView
from .views import DMTokenView, back_channel_logout, oauth_dynamic_client_registration

urlpatterns = [
    path(
        "auth/back_channel_logout/<str:backend>/",
        back_channel_logout,
        name="tpa-backchannel-logout",
    ),
    path("ibl/auth/register/", IblUserManagementView.as_view(), name="user-register"),
    path(
        "ibl-oauth/register/",
        oauth_dynamic_client_registration,
        name="ibl-oauth-dcr",
    ),
    path(
        "ibl-oauth/dmtoken/",
        DMTokenView.as_view(),
        name="ibl-oauth-dmtoken",
    ),
]

urlpatterns += api_urls.urlpatterns
