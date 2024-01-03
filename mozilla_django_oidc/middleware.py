import logging
import time
from re import Pattern as re_Pattern
from urllib.parse import quote

from django.contrib.auth import BACKEND_SESSION_KEY
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import cached_property
from django.utils.module_loading import import_string

from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import AuthorizationCodeRequestMixin

LOGGER = logging.getLogger(__name__)


class SessionRefresh(MiddlewareMixin, AuthorizationCodeRequestMixin):
    """Refreshes the session with the OIDC RP after expiry seconds

    For users authenticated with the OIDC RP, verify tokens are still valid and
    if not, force the user to re-authenticate silently.

    """

    def __init__(self, get_response):
        super().__init__(get_response)
        self.init_settings_for_authorization_code_request()
        self.OIDC_EXEMPT_URLS = self.get_settings("OIDC_EXEMPT_URLS", [])

    @cached_property
    def exempt_urls(self):
        """Generate and return a set of url paths to exempt from SessionRefresh

        This takes the value of ``settings.OIDC_EXEMPT_URLS`` and appends three
        urls that mozilla-django-oidc uses. These values can be view names or
        absolute url paths.

        :returns: list of url paths (for example "/oidc/callback/")

        """
        exempt_urls = []
        for url in self.OIDC_EXEMPT_URLS:
            if not isinstance(url, re_Pattern):
                exempt_urls.append(url)
        exempt_urls.extend(
            [
                "oidc_authentication_init",
                "oidc_authentication_callback",
                "oidc_logout",
            ]
        )

        return set(
            [url if url.startswith("/") else reverse(url) for url in exempt_urls]
        )

    @cached_property
    def exempt_url_patterns(self):
        """Generate and return a set of url patterns to exempt from SessionRefresh

        This takes the value of ``settings.OIDC_EXEMPT_URLS`` and returns the
        values that are compiled regular expression patterns.

        :returns: list of url patterns (for example,
            ``re.compile(r"/user/[0-9]+/image")``)
        """
        exempt_patterns = set()
        for url_pattern in self.OIDC_EXEMPT_URLS:
            if isinstance(url_pattern, re_Pattern):
                exempt_patterns.add(url_pattern)
        return exempt_patterns

    def is_refreshable_url(self, request):
        """Takes a request and returns whether it triggers a refresh examination

        :arg HttpRequest request:

        :returns: boolean

        """
        # Do not attempt to refresh the session if the OIDC backend is not used
        backend_session = request.session.get(BACKEND_SESSION_KEY)
        is_oidc_enabled = True
        if backend_session:
            auth_backend = import_string(backend_session)
            is_oidc_enabled = issubclass(auth_backend, OIDCAuthenticationBackend)

        return (
            request.method == "GET"
            and request.user.is_authenticated
            and is_oidc_enabled
            and request.path not in self.exempt_urls
            and not any(pat.match(request.path) for pat in self.exempt_url_patterns)
        )

    def get_extra_params(self, request):
        extra = super().get_extra_params(request)
        extra.update(prompt="none")
        return extra

    def process_request(self, request):
        if not self.is_refreshable_url(request):
            LOGGER.debug("request is not refreshable")
            return

        expiration = request.session.get("oidc_id_token_expiration", 0)
        now = time.time()
        if expiration > now:
            # The id_token is still valid, so we don't have to do anything.
            LOGGER.debug("id token is still valid (%s > %s)", expiration, now)
            return

        LOGGER.debug("id token has expired")
        # The id_token has expired, so we have to re-authenticate silently.
        redirect_url = self.get_url_for_authorization_code_request(
            request, quote_via=quote
        )
        request.session["oidc_login_next"] = request.get_full_path()

        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            # Almost all XHR request handling in client-side code struggles
            # with redirects since redirecting to a page where the user
            # is supposed to do something is extremely unlikely to work
            # in an XHR request. Make a special response for these kinds
            # of requests.
            # The use of 403 Forbidden is to match the fact that this
            # middleware doesn't really want the user in if they don't
            # refresh their session.
            response = JsonResponse({"refresh_url": redirect_url}, status=403)
            response["refresh_url"] = redirect_url
            return response
        return HttpResponseRedirect(redirect_url)
