from mock import Mock, call, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from mozilla_django_oidc.auth import OIDCAuthenticationBackend


User = get_user_model()


class OIDCAuthenticationBackendTestCase(TestCase):
    """Authentication tests."""

    @override_settings(OIDC_OP_TOKEN_ENDPOINT='https://server.example.com/token')
    @override_settings(OIDC_OP_USER_ENDPOINT='https://server.example.com/user')
    @override_settings(OIDC_RP_CLIENT_ID='example_id')
    @override_settings(OIDC_RP_CLIENT_SECRET='example_secret')
    def setUp(self):
        self.backend = OIDCAuthenticationBackend()

    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token')
    @patch('mozilla_django_oidc.auth.requests')
    def test_invalid_token(self, request_mock, token_mock):
        """Test authentication with an invalid token."""

        token_mock.return_value = None
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            'nickname': 'username',
            'email': 'email@example.com'
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock()
        post_json_mock.json.return_value = {
            'id_token': 'id_token',
            'accesss_token': 'access_token'
        }
        request_mock.post.return_value = post_json_mock
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
    @override_settings(SITE_URL='http://site-url.com')
    def test_successful_authentication_existing_user(self, token_mock, request_mock):
        """Test successful authentication for existing user."""

        user = User.objects.create_user(username='a_username',
                                        email='email@example.com')
        token_mock.return_value = True
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            'nickname': 'a_username',
            'email': 'email@example.com'
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock()
        post_json_mock.json.return_value = {
            'id_token': 'id_token',
            'access_token': 'access_granted'
        }
        request_mock.post.return_value = post_json_mock

        post_data = {
            'client_id': 'example_id',
            'client_secret': 'example_secret',
            'grant_type': 'authorization_code',
            'code': 'foo',
            'redirect_uri': 'http://site-url.com/callback/'
        }
        self.assertEqual(self.backend.authenticate(code='foo', state='bar'), user)
        token_mock.assert_called_once_with('id_token')
        request_mock.post.assert_called_once_with('https://server.example.com/token',
                                                  json=post_data,
                                                  verify=True)
        request_mock.get.assert_called_once_with(
            'https://server.example.com/user?access_token=access_granted'
        )

    @patch.object(settings, 'OIDC_USERNAME_ALGO')
    @patch('mozilla_django_oidc.auth.requests')
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token')
    @override_settings(SITE_URL='http://site-url.com')
    def test_successful_authentication_new_user(self, token_mock, request_mock, algo_mock):
        """Test successful authentication and user creation."""

        algo_mock.return_value = 'username_algo'
        token_mock.return_value = True
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            'nickname': 'a_username',
            'email': 'email@example.com'
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock()
        post_json_mock.json.return_value = {
            'id_token': 'id_token',
            'access_token': 'access_granted'
        }
        request_mock.post.return_value = post_json_mock
        post_data = {
            'client_id': 'example_id',
            'client_secret': 'example_secret',
            'grant_type': 'authorization_code',
            'code': 'foo',
            'redirect_uri': 'http://site-url.com/callback/',
        }
        self.assertEqual(User.objects.all().count(), 0)
        self.backend.authenticate(code='foo', state='bar')
        self.assertEqual(User.objects.all().count(), 1)
        user = User.objects.all()[0]
        self.assertEquals(user.email, 'email@example.com')
        self.assertEquals(user.username, 'username_algo')

        token_mock.assert_called_once_with('id_token')
        request_mock.post.assert_called_once_with('https://server.example.com/token',
                                                  json=post_data,
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

        jwt_mock.decode.return_value = {
            'aud': 'audience'
        }
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            'nickname': 'username',
            'email': 'email@example.com'
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock()
        post_json_mock.json.return_value = {
            'id_token': 'token',
            'access_token': 'access_token'
        }
        request_mock.post.return_value = post_json_mock
        self.backend.authenticate(code='foo', state='bar')
        calls = [
            call('token', verify=False),
            call('token', 'example_secret', verify=True, audience='audience')
        ]
        jwt_mock.decode.assert_has_calls(calls)

    @override_settings(OIDC_VERIFY_JWT=False)
    @patch('mozilla_django_oidc.auth.jwt')
    @patch('mozilla_django_oidc.auth.requests')
    def test_jwt_decode_params_verify_false(self, request_mock, jwt_mock):
        """Test jwt verification signature with verify False"""

        jwt_mock.decode.return_value = {
            'aud': 'audience'
        }
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            'nickname': 'username',
            'email': 'email@example.com'
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock()
        post_json_mock.json.return_value = {
            'id_token': 'token',
            'access_token': 'access_token'
        }
        request_mock.post.return_value = post_json_mock
        calls = [
            call('token', verify=False),
            call('token', 'example_secret', verify=False, audience='audience')
        ]

        self.backend.authenticate(code='foo', state='bar')
        jwt_mock.decode.assert_has_calls(calls)

    @override_settings(OIDC_CREATE_USER=False)
    @patch('mozilla_django_oidc.auth.jwt')
    @patch('mozilla_django_oidc.auth.requests')
    def test_create_user_disabled(self, request_mock, jwt_mock):
        """Test with user creation disabled and no user found."""

        jwt_mock.return_value = True
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            'nickname': 'a_username',
            'email': 'email@example.com'
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock()
        post_json_mock.json.return_value = {
            'id_token': 'id_token',
            'access_token': 'access_granted'
        }
        request_mock.post.return_value = post_json_mock
        self.assertEqual(self.backend.authenticate(code='foo', state='bar'), None)

    @patch('mozilla_django_oidc.auth.jwt')
    @patch('mozilla_django_oidc.auth.requests')
    def test_create_user_enabled(self, request_mock, jwt_mock):
        """Test with user creation enabled and no user found."""

        self.assertEqual(User.objects.filter(email='email@example.com').exists(), False)
        jwt_mock.return_value = True
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            'nickname': 'a_username',
            'email': 'email@example.com'
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock()
        post_json_mock.json.return_value = {
            'id_token': 'id_token',
            'access_token': 'access_granted'
        }
        request_mock.post.return_value = post_json_mock
        self.assertEqual(self.backend.authenticate(code='foo', state='bar'),
                         User.objects.get(email='email@example.com'))

    @patch.object(settings, 'OIDC_USERNAME_ALGO')
    @patch('mozilla_django_oidc.auth.jwt')
    @patch('mozilla_django_oidc.auth.requests')
    def test_custom_username_algo(self, request_mock, jwt_mock, algo_mock):
        """Test user creation with custom username algorithm."""

        self.assertEqual(User.objects.filter(email='email@example.com').exists(), False)
        algo_mock.return_value = 'username_algo'
        jwt_mock.return_value = True
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            'nickname': 'a_username',
            'email': 'email@example.com'
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock()
        post_json_mock.json.return_value = {
            'id_token': 'id_token',
            'access_token': 'access_granted'
        }
        request_mock.post.return_value = post_json_mock
        self.assertEqual(self.backend.authenticate(code='foo', state='bar'),
                         User.objects.get(username='username_algo'))

    @patch('mozilla_django_oidc.auth.jwt')
    @patch('mozilla_django_oidc.auth.requests')
    def test_duplicate_emails(self, request_mock, jwt_mock):
        """Test auth with two users having the same email."""

        User.objects.create(username='user1', email='email@example.com')
        User.objects.create(username='user2', email='email@example.com')
        jwt_mock.return_value = True
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            'nickname': 'a_username',
            'email': 'email@example.com'
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock()
        post_json_mock.json.return_value = {
            'id_token': 'id_token',
            'access_token': 'access_granted'
        }
        request_mock.post.return_value = post_json_mock
        self.assertEqual(self.backend.authenticate(code='foo', state='bar'), None)
