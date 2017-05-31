try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

import time

import django
from django.core.urlresolvers import reverse
from django.http import HttpResponseRedirect
from django.utils.crypto import get_random_string

from mozilla_django_oidc.utils import absolutify, import_from_settings, is_authenticated


# Django 1.11 makes changes to how middleware work. In Django 1.11+, we want to
# use the mixin so that our middleware works as is.
if tuple(django.VERSION[0:2]) >= (1, 10):
    from django.utils.deprecation import MiddlewareMixin
else:
    class MiddlewareMixin(object):
        pass


# FIXME(willkg): This doesn't appear to be used anywhere.
def logout_url():
    """Log out the user from Auth0."""
    url = 'https://' + import_from_settings('OIDC_OP_DOMAIN') + '/v2/logout'
    url += '?' + urlencode({
        'returnTo': import_from_settings('LOGOUT_REDIRECT_URL', '/'),
        'client_id': import_from_settings('OIDC_RP_CLIENT_ID')
    })
    return url


class RefreshIDToken(MiddlewareMixin):
    """Renews id_tokens after expiry seconds

    For users authenticated with an id_token, we need to check that it's still
    valid after a specific amount of time and if not, force them to
    re-authenticate silently.

    """
    def process_request(self, request):
        if ((request.method == 'GET' and
             is_authenticated(request.user) and
             not request.path.startswith('/oidc/') and
             not request.is_ajax())):
            expiration = request.session.get('oidc_id_token_expiration')
            if expiration is not None and expiration > time.time():
                # The id_token is still valid, so we don't have to do anything.
                return

            # The id_token has expired, so we have to re-authenticate silently.
            auth_url = import_from_settings('OIDC_OP_AUTHORIZATION_ENDPOINT')
            client_id = import_from_settings('OIDC_RP_CLIENT_ID')
            state = get_random_string(import_from_settings('OIDC_STATE_SIZE', 32))

            # Build the parameters as if we were doing a real auth handoff, except
            # we also include prompt=none.
            params = {
                'response_type': 'code',
                'client_id': client_id,
                'redirect_uri': absolutify(reverse('oidc_authentication_callback')),
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
