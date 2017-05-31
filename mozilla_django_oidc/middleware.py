try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

import requests
from six import string_types

import django
from django.core.cache import cache

from mozilla_django_oidc.utils import import_from_settings, is_authenticated
from mozilla_django_oidc.views import OIDCLogoutView


# Django 1.11 makes changes to how middleware work. In Django 1.11+, we want to
# use the mixin so that our middleware works as is.
if tuple(django.VERSION[0:2]) >= (1, 10):
    from django.utils.deprecation import MiddlewareMixin
else:
    class MiddlewareMixin(object):
        pass


def refresh_id_token(id_token):
    """Renews the id_token from the delegation endpoint in Auth0.

    :arg str id_token: the id token to renew

    :returns: ``id_token`` if renewed successfully or ``None``

    """
    # FIXME(willkg): Rewrite this to use authorization endpoint
    delegation_url = 'https://{0}/delegation'.format(import_from_settings('OIDC_OP_DOMAIN'))
    data = {
        'client_id': import_from_settings('OIDC_RP_CLIENT_ID'),
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'id_token': id_token,
        'api_type': 'app'
    }

    response = requests.post(delegation_url, data=data)

    if response.status_code == requests.codes.ok:
        return response.json().get('id_token')

    return


def logout_url():
    """Log out the user from Auth0."""
    # FIXME(willkg): This doesn't appear to be used anywhere.
    url = 'https://' + import_from_settings('OIDC_OP_DOMAIN') + '/v2/logout'
    url += '?' + urlencode({
        'returnTo': import_from_settings('LOGOUT_REDIRECT_URL', '/'),
        'client_id': import_from_settings('OIDC_RP_CLIENT_ID')
    })
    return url


class RefreshIDToken(MiddlewareMixin):
    """
    Bluntly stolen from mozilla/airmozilla

    For users authenticated with an id_token, we need to check that it's
    still valid after a specific amount of time.
    """

    def process_request(self, request):
        if is_authenticated(request.user) and not request.is_ajax():
            if 'oidc_id_token' not in request.session:
                return

            cache_key = 'renew_id_token:{}'.format(request.user.id)
            if cache.get(cache_key):
                # still valid, we checked recently
                return

            id_token = refresh_id_token(request.session['oidc_id_token'])

            if id_token:
                assert isinstance(id_token, string_types)
                request.session['oidc_id_token'] = id_token
                timeout = import_from_settings('OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS', 60 * 15)
                cache.set(cache_key, True, timeout)
            else:
                # If that failed, your previous id_token is not valid
                # and you need to be signed out so you can get a new
                # one.
                return OIDCLogoutView.as_view()(request)
