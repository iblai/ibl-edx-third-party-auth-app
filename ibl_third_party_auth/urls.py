"""Url configuration for the auth module."""

from django.urls import re_path

from .views import back_channel_logout
from .api import urls as api_urls


urlpatterns = [
    re_path(r'^auth/back_channel_logout/(?P<backend>\w+)$', back_channel_logout, name='tpa-backchannel-logout'),
]

urlpatterns += api_urls.urlpatterns
