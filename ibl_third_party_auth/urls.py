"""Url configuration for the auth module."""

from django.conf import settings
from django.conf.urls import url

from .views import back_channel_logout, TPALogoutView


urlpatterns = [
    url(r'^auth/back_channel_logout/(?P<backend>\w+)$', back_channel_logout, name='tpa-backchannel-logout'),
]

urlpatterns += [url(r'^logout$', TPALogoutView.as_view(), name='logout')]
