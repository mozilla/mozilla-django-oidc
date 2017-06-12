import logging
import time
try:
    from urllib.parse import urlencode
except ImportError:
    # Python < 3
    from urllib import urlencode

import django
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.utils.crypto import get_random_string

from mozilla_django_oidc.utils import absolutify, import_from_settings, is_authenticated


LOGGER = logging.getLogger(__name__)


# Django 1.10 makes changes to how middleware work. In Django 1.10+, we want to
# use the mixin so that our middleware works as is.
if django.VERSION >= (1, 10):
    from django.utils.deprecation import MiddlewareMixin
else:
    class MiddlewareMixin(object):
        pass


class RefreshIDToken(MiddlewareMixin):
    """Renews id_tokens after expiry seconds

    For users authenticated with an id_token, we need to check that it's still
    valid after a specific amount of time and if not, force them to
    re-authenticate silently.

    """
    def get_exempt_urls(self):
        """Generate and return a set of url paths to exempt from RefreshIDToken

        This takes the value of ``settings.OIDC_EXEMPT_URLS`` and appends three
        urls that mozilla-django-oidc uses. These values can be view names or
        absolute url paths.

        :returns: list of url paths (for example "/oidc/callback/")

        """
        exempt_urls = list(import_from_settings('OIDC_EXEMPT_URLS', []))
        exempt_urls.extend([
            'oidc_authentication_init',
            'oidc_authentication_callback',
            'oidc_logout',
        ])

        return [
            url if url.startswith('/') else reverse(url)
            for url in exempt_urls
        ]

    def is_refreshable_url(self, request):
        """Takes a request and returns whether it triggers a refresh examination

        :arg HttpRequest request:

        :returns: boolean

        """
        exempt_urls = self.get_exempt_urls()

        return (
            request.method == 'GET' and
            is_authenticated(request.user) and
            request.path not in exempt_urls and
            not request.is_ajax()
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
        auth_url = import_from_settings('OIDC_OP_AUTHORIZATION_ENDPOINT')
        client_id = import_from_settings('OIDC_RP_CLIENT_ID')
        state = get_random_string(import_from_settings('OIDC_STATE_SIZE', 32))

        # Build the parameters as if we were doing a real auth handoff, except
        # we also include prompt=none.
        params = {
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': absolutify(
                request,
                reverse('oidc_authentication_callback')
            ),
            'state': state,
            'scope': 'openid',
            'prompt': 'none',
        }

        if import_from_settings('OIDC_USE_NONCE', True):
            nonce = get_random_string(import_from_settings('OIDC_NONCE_SIZE', 32))
            params.update({
                'nonce': nonce
            })
            request.session['oidc_nonce'] = nonce

        request.session['oidc_state'] = state
        request.session['oidc_login_next'] = request.get_full_path()

        query = urlencode(params)
        redirect_url = '{url}?{query}'.format(url=auth_url, query=query)
        return HttpResponseRedirect(redirect_url)
