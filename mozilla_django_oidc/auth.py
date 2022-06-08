import base64
import hashlib
import json
import logging
import requests
from requests.auth import HTTPBasicAuth
# logindotgov-oidc
import secrets
import time
import jwt
# /logindotgov-oidc

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import SuspiciousOperation, ImproperlyConfigured
from django.urls import reverse
from django.utils.encoding import force_bytes, smart_str, smart_bytes
from django.utils.module_loading import import_string

from josepy.b64 import b64decode
from josepy.jwk import JWK
from josepy.jws import JWS, Header

from mozilla_django_oidc.utils import absolutify, import_from_settings

LOGGER = logging.getLogger(__name__)


def default_username_algo(unique_identifier):
    """Generate username for the Django user.

    :arg str/unicode unique_identifier: the unique_identifier to use to generate a username

    :returns: str/unicode

    """
    # bluntly stolen from django-browserid
    # store the username as a base64 encoded sha224 of the unique_identifier
    # this protects against data leakage because usernames are often
    # treated as public identifiers (so we can't use the unique_identifier).
    username = base64.urlsafe_b64encode(
        hashlib.sha1(force_bytes(unique_identifier)).digest()
    ).rstrip(b'=')

    return smart_str(username)


class OIDCAuthenticationBackend(ModelBackend):
    """Override Django's authentication."""

    def __init__(self, *args, **kwargs):
        """Initialize settings."""
        # OP = OIDC provider, or identity provider
        self.OIDC_OP_TOKEN_ENDPOINT = self.get_settings('OIDC_OP_TOKEN_ENDPOINT')
        self.OIDC_OP_USER_ENDPOINT = self.get_settings('OIDC_OP_USER_ENDPOINT')
        self.OIDC_OP_JWKS_ENDPOINT = self.get_settings('OIDC_OP_JWKS_ENDPOINT', None)
        # Sometimes the OP has a different label for the unique ID
        self.OIDC_OP_UNIQUE_IDENTIFIER = self.get_settings('OIDC_OP_UNIQUE_IDENTIFIER', 'email')
        self.OIDC_OP_CLIENT_AUTH_METHOD = self.get_settings('OIDC_OP_CLIENT_AUTH_METHOD', 'implicit_flow')
        # RP = Relying Party, or web app
        self.OIDC_RP_CLIENT_ID = self.get_settings('OIDC_RP_CLIENT_ID')
        self.OIDC_RP_CLIENT_SECRET = self.get_settings('OIDC_RP_CLIENT_SECRET')
        self.OIDC_RP_SIGN_ALGO = self.get_settings('OIDC_RP_SIGN_ALGO', 'HS256')
        self.OIDC_RP_IDP_SIGN_KEY = self.get_settings('OIDC_RP_IDP_SIGN_KEY', None)
        self.OIDC_RP_UNIQUE_IDENTIFIER = self.get_settings('OIDC_RP_UNIQUE_IDENTIFIER', 'email')

        if (self.OIDC_RP_SIGN_ALGO.startswith('RS') and
                (self.OIDC_RP_IDP_SIGN_KEY is None and self.OIDC_OP_JWKS_ENDPOINT is None)):
            msg = '{} alg requires OIDC_RP_IDP_SIGN_KEY or OIDC_OP_JWKS_ENDPOINT to be configured.'
            raise ImproperlyConfigured(msg.format(self.OIDC_RP_SIGN_ALGO))

        self.UserModel = get_user_model()

    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

    def get_idp_unique_id_value(self, claims):
        """Helper method to clarify whether we're using OP or RP unique ID"""
        return claims.get(self.OIDC_OP_UNIQUE_IDENTIFIER)

    def describe_user_by_claims(self, claims):
        unique_identifier_value = self.get_idp_unique_id_value(claims)
        return '{} {}'.format(self.OIDC_RP_UNIQUE_IDENTIFIER, unique_identifier_value)

    def filter_users_by_claims(self, claims):
        """Return all users matching the specified unique identifier."""
        # Get the unique ID value from IDP
        unique_identifier_value = self.get_idp_unique_id_value(claims)
        if not unique_identifier_value:
            return self.UserModel.objects.none()
        # Use the app label to filter
        filter_label = self.OIDC_RP_UNIQUE_IDENTIFIER + "__iexact"
        kwargs = {filter_label: unique_identifier_value}
        LOGGER.debug("filter_label", filter_label)
        LOGGER.debug("unique_identifier_value", unique_identifier_value)
        filtered_users = self.UserModel.objects.filter(**kwargs)
        LOGGER.debug("filtered_users query", filtered_users.query)

        return filtered_users

    def verify_claims(self, claims):
        """Verify the provided claims to decide if authentication should be allowed."""

        # Verify claims required by default configuration
        LOGGER.debug("verify_claims.claims (user_info", json.dumps(claims))

        # Scopes are user attributes requested, not necessarily claims
        scopes = self.get_settings('OIDC_RP_SCOPES', 'openid email')

        if 'email' in scopes.split():
            return 'email' in claims

        LOGGER.warning('Custom OIDC_RP_SCOPES defined. '
                       'You need to override `verify_claims` for custom claims verification.')

        return True

    def create_user(self, claims):
        """Return object for a newly created user account."""

        LOGGER.debug("verify_claims.claims (user_info", json.dumps(claims))
        email = claims.get('email')
        username = self.get_username(claims)

        # Create user with custom values if they're specified
        if not ((self.OIDC_RP_UNIQUE_IDENTIFIER == self.OIDC_RP_UNIQUE_IDENTIFIER == 'email') or 
            (self.OIDC_RP_UNIQUE_IDENTIFIER == self.OIDC_RP_UNIQUE_IDENTIFIER == 'username')):
            # { app_field: idp_field}
            # { "uuid": "sub_value"}
            extra_params = {self.OIDC_RP_UNIQUE_IDENTIFIER: self.get_idp_unique_id_value(claims)}
        else:
            extra_params = {}

        return self.UserModel.objects.create_user(
            email,
            username=username,
            **extra_params
        )

    def get_username(self, claims):
        """Generate username based on claims."""
        # bluntly stolen from django-browserid
        # https://github.com/mozilla/django-browserid/blob/master/django_browserid/auth.py
        username_algo = self.get_settings('OIDC_USERNAME_ALGO', None)

        if username_algo:
            if isinstance(username_algo, str):
                username_algo = import_string(username_algo)
            return username_algo(self.get_idp_unique_id_value(claims))

        return default_username_algo(self.get_idp_unique_id_value(claims))

    def update_user(self, user, claims):
        """Update existing user with new email, if necessary save, and return user"""

        user.email = claims.get("email")
        user.save()
        return user

    def _verify_jws(self, payload, key):
        """Verify the given JWS payload with the given key and return the payload"""
        jws = JWS.from_compact(payload)

        try:
            alg = jws.signature.combined.alg.name
        except KeyError:
            msg = 'No alg value found in header'
            raise SuspiciousOperation(msg)

        if alg != self.OIDC_RP_SIGN_ALGO:
            msg = "The provider algorithm {!r} does not match the client's " \
                  "OIDC_RP_SIGN_ALGO.".format(alg)
            raise SuspiciousOperation(msg)

        if isinstance(key, str):
            # Use smart_bytes here since the key string comes from settings.
            jwk = JWK.load(smart_bytes(key))
        else:
            # The key is a json returned from the IDP JWKS endpoint.
            jwk = JWK.from_json(key)

        if not jws.verify(jwk):
            msg = 'JWS token verification failed.'
            raise SuspiciousOperation(msg)

        return jws.payload

    def retrieve_matching_jwk(self, token):
        """Get the signing key by exploring the JWKS endpoint of the OP."""
        response_jwks = requests.get(
            self.OIDC_OP_JWKS_ENDPOINT,
            verify=self.get_settings('OIDC_VERIFY_SSL', True),
            timeout=self.get_settings('OIDC_TIMEOUT', None),
            proxies=self.get_settings('OIDC_PROXY', None)
        )
        response_jwks.raise_for_status()
        jwks = response_jwks.json()

        # Compute the current header from the given token to find a match
        jws = JWS.from_compact(token)
        json_header = jws.signature.protected
        header = Header.json_loads(json_header)

        key = None
        for jwk in jwks['keys']:
            if (import_from_settings("OIDC_VERIFY_KID", True)
                    and jwk['kid'] != smart_str(header.kid)):
                continue
            if 'alg' in jwk and jwk['alg'] != smart_str(header.alg):
                continue
            key = jwk
        if key is None:
            raise SuspiciousOperation('Could not find a valid JWKS.')
        return key

    def get_payload_data(self, token, key):
        """Helper method to get the payload of the JWT token."""
        if self.get_settings('OIDC_ALLOW_UNSECURED_JWT', False):
            header, payload_data, signature = token.split(b'.')
            header = json.loads(smart_str(b64decode(header)))

            # If config allows unsecured JWTs check the header and return the decoded payload
            if 'alg' in header and header['alg'] == 'none':
                return b64decode(payload_data)

        # By default fallback to verify JWT signatures
        return self._verify_jws(token, key)

    def verify_token(self, token, **kwargs):
        """Validate the token signature."""
        nonce = kwargs.get('nonce')

        token = force_bytes(token)
        if self.OIDC_RP_SIGN_ALGO.startswith('RS'):
            if self.OIDC_RP_IDP_SIGN_KEY is not None:
                key = self.OIDC_RP_IDP_SIGN_KEY
            else:
                key = self.retrieve_matching_jwk(token)
        else:
            key = self.OIDC_RP_CLIENT_SECRET

        payload_data = self.get_payload_data(token, key)

        # The 'token' will always be a byte string since it's
        # the result of base64.urlsafe_b64decode().
        # The payload is always the result of base64.urlsafe_b64decode().
        # In Python 3 and 2, that's always a byte string.
        # In Python3.6, the json.loads() function can accept a byte string
        # as it will automagically decode it to a unicode string before
        # deserializing https://bugs.python.org/issue17909
        payload = json.loads(payload_data.decode('utf-8'))
        token_nonce = payload.get('nonce')

        if self.get_settings('OIDC_USE_NONCE', True) and nonce != token_nonce:
            msg = 'JWT Nonce verification failed.'
            raise SuspiciousOperation(msg)
        return payload

    def get_token(self, payload):
        """Return token object as a dictionary.
        Borrowed from logindotgov-oidc, modified
        https://github.com/trussworks/logindotgov-oidc-py
        """

        if self.OIDC_OP_CLIENT_AUTH_METHOD == "private_key_jwt":
            jwt_args = {
                "iss": self.OIDC_RP_CLIENT_ID,
                "sub": self.OIDC_RP_CLIENT_ID,
                "aud": self.OIDC_OP_TOKEN_ENDPOINT,
                "jti": secrets.token_hex(16),
                "exp": int(time.time()) + 300,  # 5 minutes from now
            }
            LOGGER.debug("get_token.jwt_args: {}".format(json.dumps(jwt_args)))

            # Client secret needs to be pem-encoded string
            encoded_jwt = jwt.encode(
                jwt_args,
                self.OIDC_RP_CLIENT_SECRET,
                algorithm=self.OIDC_RP_SIGN_ALGO
            )
            LOGGER.debug("get_token original payload: {}".format(json.dumps(payload)))

            token_payload = {
                "client_assertion": encoded_jwt,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "code": payload.get("code"),
                "grant_type": "authorization_code",
            }

            LOGGER.debug("get_token.token_payload")
            response = requests.post(self.OIDC_OP_TOKEN_ENDPOINT, data=token_payload)
            return response.json()

        # Default implementation
        auth = None
        if self.get_settings('OIDC_TOKEN_USE_BASIC_AUTH', False):
            # When Basic auth is defined, create the Auth Header and remove secret from payload.
            user = payload.get('client_id')
            pw = payload.get('client_secret')

            auth = HTTPBasicAuth(user, pw)
            del payload['client_secret']

        response = requests.post(
            self.OIDC_OP_TOKEN_ENDPOINT,
            data=payload,
            auth=auth,
            verify=self.get_settings('OIDC_VERIFY_SSL', True),
            timeout=self.get_settings('OIDC_TIMEOUT', None),
            proxies=self.get_settings('OIDC_PROXY', None))
        response.raise_for_status()
        return response.json()

    def get_userinfo(self, access_token, id_token, payload):
        """Return user details dictionary. The id_token and payload are not used in
        the default implementation, but may be used when overriding this method"""

        user_response = requests.get(
            self.OIDC_OP_USER_ENDPOINT,
            headers={
                'Authorization': 'Bearer {0}'.format(access_token)
            },
            verify=self.get_settings('OIDC_VERIFY_SSL', True),
            timeout=self.get_settings('OIDC_TIMEOUT', None),
            proxies=self.get_settings('OIDC_PROXY', None))
        LOGGER.debug("get_userinfo.user_response: {}".format(json.dumps(user_response.json())))
        user_response.raise_for_status()
        return user_response.json()

    def authenticate(self, request, **kwargs):
        """Authenticates a user based on the OIDC code flow."""

        self.request = request
        if not self.request:
            return None

        state = self.request.GET.get('state')
        code = self.request.GET.get('code')
        nonce = kwargs.pop('nonce', None)

        if not code or not state:
            return None

        reverse_url = self.get_settings('OIDC_AUTHENTICATION_CALLBACK_URL',
                                        'oidc_authentication_callback')

        redirect_uri = absolutify(self.request, reverse(reverse_url))

        LOGGER.debug("authenticate.redirect_uri: {}".format({redirect_uri}))

        token_payload = {
            'client_id': self.OIDC_RP_CLIENT_ID,
            'client_secret': self.OIDC_RP_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
        }

        # Get the token
        token_info = self.get_token(token_payload)
        id_token = token_info.get('id_token')
        access_token = token_info.get('access_token')

        # Validate the token
        payload = self.verify_token(id_token, nonce=nonce)

        if payload:
            self.store_tokens(access_token, id_token)
            try:
                return self.get_or_create_user(access_token, id_token, payload)
            except SuspiciousOperation as exc:
                LOGGER.warning('failed to get or create user: %s', exc)
                return None

        return None

    def store_tokens(self, access_token, id_token):
        """Store OIDC tokens."""
        session = self.request.session

        if self.get_settings('OIDC_STORE_ACCESS_TOKEN', False):
            session['oidc_access_token'] = access_token

        if self.get_settings('OIDC_STORE_ID_TOKEN', False):
            session['oidc_id_token'] = id_token

    def get_or_create_user(self, access_token, id_token, payload):
        """Returns a User instance if 1 user is found. Creates a user if not found
        and configured to do so. Returns nothing if multiple users are matched."""

        LOGGER.debug("get_or_create_user.access_token", access_token)
        LOGGER.debug("get_or_create_user.id_token", id_token)
        LOGGER.debug("get_or_create_user.json.dumps(payload)", json.dumps(payload))

        user_info = self.get_userinfo(access_token, id_token, payload)

        claims_verified = self.verify_claims(user_info)
        if not claims_verified:
            msg = 'Claims verification failed'
            raise SuspiciousOperation(msg)

        # unique identifier-based filtering
        users = self.filter_users_by_claims(user_info)

        if len(users) == 1:
            return self.update_user(users[0], user_info)
        elif len(users) > 1:
            # In the rare case that two user accounts have the same unique identifier,
            # bail. Randomly selecting one seems really wrong.
            msg = 'Multiple users returned'
            raise SuspiciousOperation(msg)
        elif self.get_settings('OIDC_CREATE_USER', True):
            user = self.create_user(user_info)
            return user
        else:
            LOGGER.debug('Login failed: No user with %s found, and '
                         'OIDC_CREATE_USER is False',
                         self.describe_user_by_claims(user_info))
            return None

    def get_user(self, user_id):
        """Return a user based on the id."""

        try:
            return self.UserModel.objects.get(pk=user_id)
        except self.UserModel.DoesNotExist:
            return None
