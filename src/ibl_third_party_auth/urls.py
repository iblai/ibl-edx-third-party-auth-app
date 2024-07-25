"""Url configuration for the auth module."""

from django.urls import path

from .api import urls as api_urls
from .registration import UserManagementView
from .views import back_channel_logout

urlpatterns = [
    path('auth/back_channel_logout/<str:backend>/', back_channel_logout, name='tpa-backchannel-logout'),
    path('ibl/auth/register/', UserManagementView.as_view(), name='user-register'),
]

urlpatterns += api_urls.urlpatterns