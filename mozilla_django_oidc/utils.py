import warnings

try:
    from urllib.request import parse_http_list, parse_keqv_list
except ImportError:
    # python < 3
    from urllib2 import parse_http_list, parse_keqv_list

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.crypto import get_random_string


def parse_www_authenticate_header(header):
    """
    Convert a WWW-Authentication header into a dict that can be used
    in a JSON response.
    """
    items = parse_http_list(header)
    return parse_keqv_list(items)


def import_from_settings(attr, *args):
    """
    Load an attribute from the django settings.

    :raises:
        ImproperlyConfigured
    """
    try:
        if args:
            return getattr(settings, attr, args[0])
        return getattr(settings, attr)
    except AttributeError:
        raise ImproperlyConfigured('Setting {0} not found'.format(attr))


def absolutify(request, path):
    """Return the absolute URL of a path."""
    return request.build_absolute_uri(path)


def is_authenticated(user):
    """return True if the user is authenticated.
    This is necessary because in Django 1.10 the `user.is_authenticated`
    stopped being a method and is now a property.
    Actually `user.is_authenticated()` actually works, thanks to a backwards
    compat trick in Django. But in Django 2.0 it will cease to work
    as a callable method.
    """

    msg = '`is_authenticated()` is going to be removed in mozilla-django-oidc v 2.x'
    warnings.warn(msg, DeprecationWarning)
    return user.is_authenticated


def add_state_and_nonce_to_session(request, state, params):
    nonce = None
    if import_from_settings('OIDC_USE_NONCE', True):
        nonce = get_random_string(import_from_settings('OIDC_NONCE_SIZE', 32))
        params.update({
            'nonce': nonce
        })

    # Store Nonce with the state parameter in the session "oidc_states" dictionary.
    # The dictionary can store multiple state/nonce combinations to allow parallel
    # authentication flows which would otherwise overwrite state/nonce values!

    # Initialize 'oidc_states' dictionary. Make sure the dictionary does not get
    # too big by resetting the dictionary if there are more than 20 entries
    # (unlikely to reach so many parallel login sessions at the same time).
    if 'oidc_states' not in request.session or \
            not isinstance(request.session['oidc_states'], dict) or \
            len(request.session['oidc_states']) > 20:
        request.session['oidc_states'] = {}

    request.session['oidc_states'][state] = nonce
