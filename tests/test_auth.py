from mock import patch

from django.contrib.auth import get_user_model
from django.core.urlresolvers import reverse
from django.test import TestCase, override_settings

from mozilla_django_oidc.auth import OIDCAuthenticationBackend


User = get_user_model()


class OIDCAuthenticationBackendTestCase(TestCase):
    """Authentication tests."""

    @override_settings(OIDC_OP_TOKEN_ENDPOINT='https://server.example.com/token')
    @override_settings(OIDC_OP_USER_ENDPOINT='https://server.example.com/user')
    @override_settings(OIDC_OP_CLIENT_ID='example_id')
    @override_settings(OIDC_OP_CLIENT_SECRET='example_secret')
    def setUp(self):
        self.backend = OIDCAuthenticationBackend()

    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token')
    @patch('mozilla_django_oidc.auth.requests')
    def test_invalid_token(self, request_mock, token_mock):
        """Test authentication with an invalid token."""

        token_mock.return_value = None
        request_mock.get.return_value = {
            'username': 'username',
            'verified_email': 'email@example.com'
        }
        request_mock.post.return_value = {
            'id_token': 'id_token',
            'accesss_token': 'access_token'
        }
        self.assertEqual(self.backend.authenticate(code='foo', state='bar'), None)

    def test_get_user(self):
        """Test get_user method with valid user."""

        user = User.objects.create_user('example_username')
        self.assertEqual(self.backend.get_user(user.pk), user)

    def test_get_invalid_user(self):
        """Test get_user method with non existing user."""

        self.assertEqual(self.backend.get_user(user_id=1), None)

    @patch('mozilla_django_oidc.auth.requests')
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token')
    def test_successful_authentication_existing_user(self, token_mock, request_mock):
        """Test successful authentication for existing user."""

        user = User.objects.create_user(username='a_username',
                                        email='email@example.com')
        token_mock.return_value = True
        request_mock.get.return_value = {
            'username': 'a_username',
            'verified_email': 'email@example.com'
        }
        request_mock.post.return_value = {
            'id_token': 'id_token',
            'access_token': 'access_granted'
        }
        post_data = {
            'client_id': 'example_id',
            'client_secret': 'example_secret',
            'grand_type': 'authorization_code',
            'code': 'foo',
            'redirect_url': reverse('oidc_authentication_callback')
        }
        self.assertEqual(self.backend.authenticate(code='foo', state='bar'), user)
        token_mock.assert_called_once_with('id_token')
        request_mock.post.assert_called_once_with('https://server.example.com/token',
                                                  data=post_data,
                                                  verify=True)
        request_mock.get.assert_called_once_with(
            'https://server.example.com/user?access_token=access_granted'
        )

    @patch('mozilla_django_oidc.auth.requests')
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token')
    def test_successful_authentication_new_user(self, token_mock, request_mock):
        """Test successful authentication and user creation."""

        token_mock.return_value = True
        request_mock.get.return_value = {
            'username': 'a_username',
            'verified_email': 'email@example.com'
        }
        request_mock.post.return_value = {
            'id_token': 'id_token',
            'access_token': 'access_granted'
        }
        post_data = {
            'client_id': 'example_id',
            'client_secret': 'example_secret',
            'grand_type': 'authorization_code',
            'code': 'foo',
            'redirect_url': reverse('oidc_authentication_callback')
        }
        self.assertEqual(User.objects.all().count(), 0)
        self.backend.authenticate(code='foo', state='bar')
        self.assertEqual(User.objects.all().count(), 1)
        user = User.objects.all()[0]
        self.assertEquals(user.email, 'email@example.com')
        self.assertEquals(user.username, 'a_username')

        token_mock.assert_called_once_with('id_token')
        request_mock.post.assert_called_once_with('https://server.example.com/token',
                                                  data=post_data,
                                                  verify=True)
        request_mock.get.assert_called_once_with(
            'https://server.example.com/user?access_token=access_granted'
        )

    def test_authenticate_no_code_no_state(self):
        """Test authenticate with wrong parameters."""

        self.assertEqual(self.backend.authenticate(code='', state=''), None)

    @patch('mozilla_django_oidc.auth.jwt')
    @patch('mozilla_django_oidc.auth.requests')
    def test_jwt_decode_params(self, request_mock, jwt_mock):
        """Test jwt verification signature."""

        request_mock.get.return_value = {
            'username': 'username',
            'verified_email': 'email@example.com'
        }
        request_mock.post.return_value = {
            'id_token': 'token',
            'access_token': 'access_token'
        }
        self.backend.authenticate(code='foo', state='bar')
        jwt_mock.decode.assert_called_once_with('token', 'example_secret', verify=True)

    @override_settings(OIDC_VERIFY_JWT=False)
    @patch('mozilla_django_oidc.auth.jwt')
    @patch('mozilla_django_oidc.auth.requests')
    def test_jwt_decode_params_verify_false(self, request_mock, jwt_mock):
        """Test jwt verification signature with verify False"""

        request_mock.get.return_value = {
            'username': 'username',
            'verified_email': 'email@example.com'
        }
        request_mock.post.return_value = {
            'id_token': 'token',
            'access_token': 'access_token'
        }
        self.backend.authenticate(code='foo', state='bar')
        jwt_mock.decode.assert_called_once_with('token', 'example_secret', verify=False)
