import logging
import time
import warnings

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from urllib.request import parse_http_list, parse_keqv_list


LOGGER = logging.getLogger(__name__)


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
    """
    Stores the `state` and `nonce` parameters in a session dictionary including the time when it
    was added. The dictionary can contain multiple state/nonce combinations to allow parallel
    logins with multiple browser sessions.
    To keep the session space to a reasonable size, the dictionary is kept at 50 state/nonce
    combinations maximum.
    """
    nonce = params.get('nonce')

    # Store Nonce with the State parameter in the session "oidc_states" dictionary.
    # The dictionary can store multiple State/Nonce combinations to allow parallel
    # authentication flows which would otherwise overwrite State/Nonce values!
    # The "oidc_states" dictionary uses the state as key and as value a dictionary with "nonce"
    # and "added_on". "added_on" contains the time when the state was added to the session.
    # With this value, the oldest element can be found and deleted from the session.
    if 'oidc_states' not in request.session or \
            not isinstance(request.session['oidc_states'], dict):
        request.session['oidc_states'] = {}

    # Make sure that the State/Nonce dictionary in the session does not get too big.
    # If the number of State/Nonce combinations reaches a certain threshold, remove the oldest
    # state by finding out
    # which element has the oldest "add_on" time.
    limit = import_from_settings('OIDC_MAX_STATES', 50)
    if len(request.session['oidc_states']) >= limit:
        LOGGER.info(
            'User has more than {} "oidc_states" in his session, '
            'deleting the oldest one!'.format(limit)
        )
        oldest_state = None
        oldest_added_on = time.time()
        for item_state, item in request.session['oidc_states'].items():
            if item['added_on'] < oldest_added_on:
                oldest_state = item_state
                oldest_added_on = item['added_on']
        if oldest_state:
            del request.session['oidc_states'][oldest_state]

    request.session['oidc_states'][state] = {
        'nonce': nonce,
        'added_on': time.time(),
    }
