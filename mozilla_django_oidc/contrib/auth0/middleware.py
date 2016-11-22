from django.core.cache import cache

from six import string_types

from mozilla_django_oidc.contrib.auth0.utils import refresh_id_token
from mozilla_django_oidc.utils import import_from_settings
from mozilla_django_oidc.views import OIDCLogoutView


class RefreshIDToken(object):
    """
    Bluntly stolen from mozilla/airmozilla

    For users authenticated with an id_token, we need to check that it's
    still valid after a specific amount of time.
    """

    def process_request(self, request):
        if request.user.is_authenticated() and not request.is_ajax():

            if 'oidc_id_token' not in request.session:
                return None

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
