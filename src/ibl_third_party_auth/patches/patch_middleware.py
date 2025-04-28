import logging
from typing import Any, Optional

import six.moves.urllib.parse
from common.djangoapps.student.helpers import get_next_url_for_login_page
from common.djangoapps.third_party_auth import middleware, pipeline
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from django.utils.translation import gettext as _
from requests import HTTPError
from social_django.middleware import SocialAuthExceptionMiddleware

log = logging.getLogger(__name__)


class IBLExceptionMiddleware(SocialAuthExceptionMiddleware, MiddlewareMixin):
    """Custom middleware that handles conditional redirection."""

    def get_redirect_uri(self, request: Any, exception: Exception) -> str:
        """Get the redirect URI for the exception."""
        log.debug(
            "Getting redirect URI for exception",
            extra={"exception_type": type(exception).__name__},
        )

        # Fall back to django settings's SOCIAL_AUTH_LOGIN_ERROR_URL.
        redirect_uri = super().get_redirect_uri(request, exception)

        # Safe because it's already been validated by pipeline.parse_query_params
        auth_entry = request.session.get(pipeline.AUTH_ENTRY_KEY)
        log.debug("Auth entry from session", extra={"auth_entry": auth_entry})

        # Check if we have an auth entry key we can use instead
        if auth_entry and auth_entry in pipeline.AUTH_DISPATCH_URLS:
            redirect_uri = pipeline.AUTH_DISPATCH_URLS[auth_entry]
            log.debug("Using auth dispatch URL", extra={"redirect_uri": redirect_uri})

        return redirect_uri

    def process_exception(self, request: Any, exception: Exception) -> Optional[Any]:
        """Handles specific exception raised by Python Social Auth eg HTTPError."""
        log.exception(
            "Processing social auth exception",
            extra={
                "exception_type": type(exception).__name__,
                "referer": request.META.get("HTTP_REFERER", ""),
                "has_response": hasattr(exception, "response"),
            },
        )

        # Check if the exception has the 'response' attribute
        if hasattr(exception, "response"):
            log.info(f"exception.response.content={exception.response.content}")
        else:
            log.info("Exception does not have a 'response' attribute.")
        referer_url = request.META.get("HTTP_REFERER", "")

        if (
            referer_url
            and isinstance(exception, HTTPError)
            and exception.response.status_code == 502
        ):
            referer_url = six.moves.urllib.parse.urlparse(referer_url).path
            if referer_url == reverse("signin_user"):
                log.warning(
                    "502 error on signin page",
                    extra={
                        "referer_url": referer_url,
                        "status_code": exception.response.status_code,
                    },
                )
                messages.error(
                    request,
                    _("Unable to connect with the external provider, please try again"),
                    extra_tags="social-auth",
                )
                redirect_url = get_next_url_for_login_page(request)
                return redirect("/login?next=" + redirect_url)

        return super().process_exception(request, exception)


def patch():
    """Patch the middleware with our implementation."""
    log.info("Starting middleware patch application")
    try:
        middleware.ExceptionMiddleware = IBLExceptionMiddleware
        log.info("Successfully patched ExceptionMiddleware")
    except Exception as e:
        log.exception("Failed to apply middleware patch", extra={"error": str(e)})
        raise
