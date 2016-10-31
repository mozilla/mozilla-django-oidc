import base64
import jwt
import requests

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.core.urlresolvers import reverse

from mozilla_django_oidc.utils import absolutify, import_from_settings


class OIDCAuthenticationBackend(object):
    """Override Django's authentication."""

    def __init__(self, *args, **kwargs):
        """Initialize settings."""
        self.OIDC_OP_TOKEN_ENDPOINT = import_from_settings('OIDC_OP_TOKEN_ENDPOINT')
        self.OIDC_OP_USER_ENDPOINT = import_from_settings('OIDC_OP_USER_ENDPOINT')
        self.OIDC_OP_CLIENT_ID = import_from_settings('OIDC_OP_CLIENT_ID')
        self.OIDC_OP_CLIENT_SECRET = import_from_settings('OIDC_OP_CLIENT_SECRET')

        self.UserModel = get_user_model()

    def verify_token(self, token, **kwargs):
        """Validate the token signature."""

        # Get JWT audience without signature verification
        audience = jwt.decode(token, verify=False)['aud']

        secret = self.OIDC_OP_CLIENT_SECRET
        if import_from_settings('OIDC_RP_CLIENT_SECRET_ENCODED', False):
            secret = base64.urlsafe_b64decode(self.OIDC_OP_CLIENT_SECRET)

        return jwt.decode(token, secret,
                          verify=import_from_settings('OIDC_VERIFY_JWT', True),
                          audience=audience)

    def authenticate(self, code=None, state=None):
        """Authenticates a user based on the OIDC code flow."""

        if not code or not state:
            return None

        token_payload = {
            'client_id': self.OIDC_OP_CLIENT_ID,
            'client_secret': self.OIDC_OP_CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': absolutify(reverse('oidc_authentication_callback'))
        }

        # Get the token
        response = requests.post(self.OIDC_OP_TOKEN_ENDPOINT,
                                 json=token_payload,
                                 verify=import_from_settings('VERIFY_SSL', True))
        # Validate the token
        token_response = response.json()
        payload = self.verify_token(token_response.get('id_token'))

        if payload:
            query = urlencode({
                'access_token': token_response.get('access_token')
            })
            user_response = requests.get('{url}?{query}'.format(url=self.OIDC_OP_USER_ENDPOINT,
                                                                query=query))
            user_info = user_response.json()

            try:
                return self.UserModel.objects.get(email=user_info['email'])
            except self.UserModel.DoesNotExist:
                return self.UserModel.objects.create_user(username=user_info['nickname'],
                                                          email=user_info['email'])
        return None

    def get_user(self, user_id):
        """Return a user based on the id."""

        try:
            return self.UserModel.objects.get(pk=user_id)
        except self.UserModel.DoesNotExist:
            return None
