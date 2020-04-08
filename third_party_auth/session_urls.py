"""Session management URLS in their own file so only they can be included
in the CMS without including all third_party_auth urls
"""
from django.conf.urls import url
from .views import check_session_rp_iframe

urlpatterns = [
    url(r'^check-session-rp$', check_session_rp_iframe,
        name='tpa-check-session-rp-iframe'),
]