import logging
import time

from django.contrib.auth import BACKEND_SESSION_KEY
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import cached_property
from django.utils.module_loading import import_string

from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import (absolutify,
                                       add_state_and_nonce_to_session,
                                       import_from_settings)

from urllib.parse import quote, urlencode

try:
    # Python 3.7 or later
    from re import Pattern as re_Pattern
except ImportError:
    # Python 3.6 or earlier
    from re import _pattern_type as re_Pattern


LOGGER = logging.getLogger(__name__)


class SessionRefresh(MiddlewareMixin):
    """Refreshes the session with the OIDC RP after expiry seconds

    For users authenticated with the OIDC RP, verify tokens are still valid and
    if not, force the user to re-authenticate silently.

    """

    def __init__(self, *args, **kwargs):
        super(SessionRefresh, self).__init__(*args, **kwargs)
        self.OIDC_EXEMPT_URLS = self.get_settings('OIDC_EXEMPT_URLS', [])
        self.OIDC_OP_AUTHORIZATION_ENDPOINT = self.get_settings('OIDC_OP_AUTHORIZATION_ENDPOINT')
        self.OIDC_RP_CLIENT_ID = self.get_settings('OIDC_RP_CLIENT_ID')
        self.OIDC_STATE_SIZE = self.get_settings('OIDC_STATE_SIZE', 32)
        self.OIDC_AUTHENTICATION_CALLBACK_URL = self.get_settings(
            'OIDC_AUTHENTICATION_CALLBACK_URL',
            'oidc_authentication_callback',
        )
        self.OIDC_RP_SCOPES = self.get_settings('OIDC_RP_SCOPES', 'openid email')
        self.OIDC_USE_NONCE = self.get_settings('OIDC_USE_NONCE', True)
        self.OIDC_NONCE_SIZE = self.get_settings('OIDC_NONCE_SIZE', 32)

    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

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
        exempt_urls.extend([
            'oidc_authentication_init',
            'oidc_authentication_callback',
            'oidc_logout',
        ])

        return set([
            url if url.startswith('/') else reverse(url)
            for url in exempt_urls
        ])

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
            request.method == 'GET' and
            request.user.is_authenticated and
            is_oidc_enabled and
            request.path not in self.exempt_urls and
            not any(pat.match(request.path) for pat in self.exempt_url_patterns)
        )

    def process_request(self, request):
        if not self.is_refreshable_url(request):
            LOGGER.debug('request is not refreshable')
            return

        expiration = request.session.get('oidc_id_token_expiration', 0)
        now = time.time()
        if expiration > now:
            # The id_token is still valid, so we don't have to do anything.
            LOGGER.debug('id token is still valid (%s > %s)', expiration, now)
            return

        LOGGER.debug('id token has expired')
        # The id_token has expired, so we have to re-authenticate silently.
        auth_url = self.OIDC_OP_AUTHORIZATION_ENDPOINT
        client_id = self.OIDC_RP_CLIENT_ID
        state = get_random_string(self.OIDC_STATE_SIZE)

        # Build the parameters as if we were doing a real auth handoff, except
        # we also include prompt=none.
        params = {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': absolutify(
                request,
                reverse(self.OIDC_AUTHENTICATION_CALLBACK_URL)
            ),
            'state': state,
            'scope': self.OIDC_RP_SCOPES,
            'prompt': 'none',
        }

        if self.OIDC_USE_NONCE:
            nonce = get_random_string(self.OIDC_NONCE_SIZE)
            params.update({
                'nonce': nonce
            })

        add_state_and_nonce_to_session(request, state, params)

        request.session['oidc_login_next'] = request.get_full_path()

        query = urlencode(params, quote_via=quote)
        redirect_url = '{url}?{query}'.format(url=auth_url, query=query)
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            # Almost all XHR request handling in client-side code struggles
            # with redirects since redirecting to a page where the user
            # is supposed to do something is extremely unlikely to work
            # in an XHR request. Make a special response for these kinds
            # of requests.
            # The use of 403 Forbidden is to match the fact that this
            # middleware doesn't really want the user in if they don't
            # refresh their session.
            response = JsonResponse({'refresh_url': redirect_url}, status=403)
            response['refresh_url'] = redirect_url
            return response
        return HttpResponseRedirect(redirect_url)
