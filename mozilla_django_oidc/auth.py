import base64
import hashlib
import json
import logging
import requests

from django.utils.encoding import smart_bytes, smart_text
from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation
from django.core.urlresolvers import reverse

from jose import jws

from mozilla_django_oidc.utils import absolutify, import_from_settings


LOGGER = logging.getLogger(__name__)


def default_username_algo(email):
    """Generate username for the Django user.

    :arg str/unicode email: the email address to use to generate a username

    :returns: str/unicode

    """
    # bluntly stolen from django-browserid
    # store the username as a base64 encoded sha224 of the email address
    # this protects against data leakage because usernames are often
    # treated as public identifiers (so we can't use the email address).
    username = base64.urlsafe_b64encode(
        hashlib.sha1(smart_bytes(email)).digest()
    ).rstrip(b'=')

    return smart_text(username)


class OIDCAuthenticationBackend(object):
    """Override Django's authentication."""

    def __init__(self, *args, **kwargs):
        """Initialize settings."""
        self.OIDC_OP_TOKEN_ENDPOINT = import_from_settings('OIDC_OP_TOKEN_ENDPOINT')
        self.OIDC_OP_USER_ENDPOINT = import_from_settings('OIDC_OP_USER_ENDPOINT')
        self.OIDC_RP_CLIENT_ID = import_from_settings('OIDC_RP_CLIENT_ID')
        self.OIDC_RP_CLIENT_SECRET = import_from_settings('OIDC_RP_CLIENT_SECRET')

        self.UserModel = get_user_model()

    def filter_users_by_claims(self, claims):
        """Return all users matching the specified email."""
        email = claims.get('email')
        if not email:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(email__iexact=email)

    def create_user(self, claims):
        """Return object for a newly created user account."""
        # bluntly stolen from django-browserid
        # https://github.com/mozilla/django-browserid/blob/master/django_browserid/auth.py

        username_algo = import_from_settings('OIDC_USERNAME_ALGO', None)
        email = claims.get('email')
        if not email:
            return None

        if username_algo:
            username = username_algo(email)
        else:
            username = default_username_algo(email)

        return self.UserModel.objects.create_user(username, email)

    def verify_token(self, token, **kwargs):
        """Validate the token signature."""
        nonce = kwargs.get('nonce')

        # Verify the token
        verified_token = jws.verify(
            token,
            self.OIDC_RP_CLIENT_SECRET,
            algorithms=['HS256']
        )
        # The 'verified_token' will always be a byte string since it's
        # the result of base64.urlsafe_b64decode().
        # The payload is always the result of base64.urlsafe_b64decode().
        # In Python 3 and 2, that's always a byte string.
        # In Python3.6, the json.loads() function can accept a byte string
        # as it will automagically decode it to a unicode string before
        # deserializing https://bugs.python.org/issue17909
        token_nonce = json.loads(verified_token.decode('utf-8')).get('nonce')

        if import_from_settings('OIDC_USE_NONCE', True) and nonce != token_nonce:
            msg = 'JWT Nonce verification failed.'
            raise SuspiciousOperation(msg)
        return True

    def authenticate(self, **kwargs):
        """Authenticates a user based on the OIDC code flow."""

        self.request = kwargs.pop('request', None)
        if not self.request:
            return None

        state = self.request.GET.get('state')
        code = self.request.GET.get('code')
        nonce = kwargs.pop('nonce', None)
        session = self.request.session

        if not code or not state:
            raise SuspiciousOperation('Code or state not found.')

        token_payload = {
            'client_id': self.OIDC_RP_CLIENT_ID,
            'client_secret': self.OIDC_RP_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': absolutify(
                self.request,
                reverse('oidc_authentication_callback')
            ),
        }

        # Get the token
        response = requests.post(self.OIDC_OP_TOKEN_ENDPOINT,
                                 data=token_payload,
                                 verify=import_from_settings('OIDC_VERIFY_SSL', True))
        response.raise_for_status()

        # Validate the token
        token_response = response.json()
        id_token = token_response.get('id_token')
        if self.verify_token(id_token, nonce=nonce):
            access_token = token_response.get('access_token')

            if import_from_settings('OIDC_STORE_ACCESS_TOKEN', False):
                session['oidc_id_token'] = id_token

            user_response = requests.get(self.OIDC_OP_USER_ENDPOINT,
                                         headers={
                                             'Authorization': 'Bearer {0}'.format(access_token)
                                         })
            user_response.raise_for_status()

            user_info = user_response.json()
            email = user_info.get('email')

            # email based filtering
            users = self.filter_users_by_claims(user_info)

            if len(users) == 1:
                return users[0]
            elif len(users) > 1:
                # In the rare case that two user accounts have the same email address,
                # log and bail. Randomly selecting one seems really wrong.
                LOGGER.warn('Multiple users with email address %s.', email)
                return None
            elif import_from_settings('OIDC_CREATE_USER', True):
                user = self.create_user(user_info)
                return user
            else:
                LOGGER.debug('Login failed: No user with email %s found, and '
                             'OIDC_CREATE_USER is False', email)
                return None
        return None

    def get_user(self, user_id):
        """Return a user based on the id."""

        try:
            return self.UserModel.objects.get(pk=user_id)
        except self.UserModel.DoesNotExist:
            return None
