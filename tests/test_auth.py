import json
from mock import Mock, call, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation
from django.test import RequestFactory, TestCase, override_settings
from django.utils import six
from django.utils.encoding import force_bytes

from mozilla_django_oidc.auth import (
    default_username_algo,
    OIDCAuthenticationBackend,
)


User = get_user_model()


class DefaultUsernameAlgoTestCase(TestCase):
    def run_test(self, data, expected):
        actual = default_username_algo(data)
        self.assertEqual(actual, expected)
        self.assertEqual(type(actual), type(expected))

    def test_empty(self):
        if six.PY2:
            self.run_test('', u'2jmj7l5rSw0yVb_vlWAYkK_YBwk')
            self.run_test(u'', u'2jmj7l5rSw0yVb_vlWAYkK_YBwk')
        else:
            self.run_test('', '2jmj7l5rSw0yVb_vlWAYkK_YBwk')

    def test_email(self):
        if six.PY2:
            self.run_test('janet@example.com', u'VUCUpl08JVpFeAFKBYkAjLhsQ1c')
            self.run_test(u'janet@example.com', u'VUCUpl08JVpFeAFKBYkAjLhsQ1c')
        else:
            self.run_test('janet@example.com', 'VUCUpl08JVpFeAFKBYkAjLhsQ1c')


class OIDCAuthenticationBackendTestCase(TestCase):
    """Authentication tests."""

    @override_settings(OIDC_OP_TOKEN_ENDPOINT='https://server.example.com/token')
    @override_settings(OIDC_OP_USER_ENDPOINT='https://server.example.com/user')
    @override_settings(OIDC_RP_CLIENT_ID='example_id')
    @override_settings(OIDC_RP_CLIENT_SECRET='client_secret')
    def setUp(self):
        self.backend = OIDCAuthenticationBackend()

    def test_missing_request_arg(self):
        """Test authentication returns `None` when `request` is not provided."""
        self.assertEqual(self.backend.authenticate(request=None), None)

    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token')
    @patch('mozilla_django_oidc.auth.requests')
    def test_invalid_token(self, request_mock, token_mock):
        """Test authentication with an invalid token."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

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
        self.assertEqual(self.backend.authenticate(request=auth_request), None)

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
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

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
            'client_secret': 'client_secret',
            'grant_type': 'authorization_code',
            'code': 'foo',
            'redirect_uri': 'http://testserver/callback/'
        }
        self.assertEqual(self.backend.authenticate(request=auth_request), user)
        token_mock.assert_called_once_with('id_token', nonce=None)
        request_mock.post.assert_called_once_with('https://server.example.com/token',
                                                  data=post_data,
                                                  verify=True)
        request_mock.get.assert_called_once_with(
            'https://server.example.com/user',
            headers={'Authorization': 'Bearer access_granted'},
            verify=True
        )

    @override_settings(OIDC_STORE_ACCESS_TOKEN=True)
    @override_settings(OIDC_STORE_ID_TOKEN=True)
    @patch('mozilla_django_oidc.auth.requests')
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token')
    def test_successful_authentication_existing_user_upper_case(self, token_mock, request_mock):
        """Test successful authentication for existing user regardless of email case."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        user = User.objects.create_user(username='a_username',
                                        email='EMAIL@EXAMPLE.COM')
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
            'client_secret': 'client_secret',
            'grant_type': 'authorization_code',
            'code': 'foo',
            'redirect_uri': 'http://testserver/callback/'
        }
        self.assertEqual(self.backend.authenticate(request=auth_request), user)
        token_mock.assert_called_once_with('id_token', nonce=None)
        request_mock.post.assert_called_once_with('https://server.example.com/token',
                                                  data=post_data,
                                                  verify=True)
        request_mock.get.assert_called_once_with(
            'https://server.example.com/user',
            headers={'Authorization': 'Bearer access_granted'},
            verify=True
        )
        self.assertEqual(auth_request.session.get('oidc_id_token'), 'id_token')
        self.assertEqual(auth_request.session.get('oidc_access_token'), 'access_granted')

    @patch('mozilla_django_oidc.auth.requests')
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token')
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_claims')
    def test_failed_authentication_verify_claims(self, claims_mock, token_mock, request_mock):
        """Test successful authentication for existing user."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        User.objects.create_user(username='a_username',
                                 email='email@example.com')
        token_mock.return_value = True
        claims_mock.return_value = False
        get_json_mock = Mock()
        claims_response = {
            'nickname': 'a_username',
            'email': 'email@example.com'
        }
        get_json_mock.json.return_value = claims_response
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock()
        post_json_mock.json.return_value = {
            'id_token': 'id_token',
            'access_token': 'access_granted'
        }
        request_mock.post.return_value = post_json_mock

        post_data = {
            'client_id': 'example_id',
            'client_secret': 'client_secret',
            'grant_type': 'authorization_code',
            'code': 'foo',
            'redirect_uri': 'http://testserver/callback/'
        }
        self.assertIsNone(self.backend.authenticate(request=auth_request))
        token_mock.assert_called_once_with('id_token', nonce=None)
        claims_mock.assert_called_once_with(claims_response)
        request_mock.post.assert_called_once_with('https://server.example.com/token',
                                                  data=post_data,
                                                  verify=True)
        request_mock.get.assert_called_once_with(
            'https://server.example.com/user',
            headers={'Authorization': 'Bearer access_granted'},
            verify=True
        )

    @patch.object(settings, 'OIDC_USERNAME_ALGO')
    @patch('mozilla_django_oidc.auth.requests')
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token')
    def test_successful_authentication_new_user(self, token_mock, request_mock, algo_mock):
        """Test successful authentication and user creation."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

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
            'client_secret': 'client_secret',
            'grant_type': 'authorization_code',
            'code': 'foo',
            'redirect_uri': 'http://testserver/callback/',
        }
        self.assertEqual(User.objects.all().count(), 0)
        self.backend.authenticate(request=auth_request)
        self.assertEqual(User.objects.all().count(), 1)
        user = User.objects.all()[0]
        self.assertEquals(user.email, 'email@example.com')
        self.assertEquals(user.username, 'username_algo')

        token_mock.assert_called_once_with('id_token', nonce=None)
        request_mock.post.assert_called_once_with('https://server.example.com/token',
                                                  data=post_data,
                                                  verify=True)
        request_mock.get.assert_called_once_with(
            'https://server.example.com/user',
            headers={'Authorization': 'Bearer access_granted'},
            verify=True
        )

    def test_authenticate_no_code_no_state(self):
        """Test authenticate with wrong parameters."""

        # there are no GET params
        request = RequestFactory().get('/foo')
        request.session = {}
        with self.assertRaisesMessage(SuspiciousOperation, 'Code or state not found'):
            self.backend.authenticate(request=request)

    @override_settings(OIDC_USE_NONCE=False)
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws')
    @patch('mozilla_django_oidc.auth.requests')
    def test_jwt_decode_params(self, request_mock, jws_mock):
        """Test jwt verification signature."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        jws_mock.return_value = json.dumps({
            'aud': 'audience'
        }).encode('utf-8')
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
        self.backend.authenticate(request=auth_request)
        calls = [
            call(force_bytes('token'), 'client_secret')
        ]
        jws_mock.assert_has_calls(calls)

    @override_settings(OIDC_VERIFY_JWT=False)
    @override_settings(OIDC_USE_NONCE=False)
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws')
    @patch('mozilla_django_oidc.auth.requests')
    def test_jwt_decode_params_verify_false(self, request_mock, jws_mock):
        """Test jwt verification signature with verify False"""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        jws_mock.return_value = json.dumps({
            'aud': 'audience'
        }).encode('utf-8')
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
            call(force_bytes('token'), 'client_secret')
        ]
        self.backend.authenticate(request=auth_request)
        jws_mock.assert_has_calls(calls)

    @override_settings(OIDC_USE_NONCE=True)
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws')
    def test_jwt_failed_nonce(self, jws_mock):
        """Test Nonce verification."""

        jws_mock.return_value = json.dumps({
            'nonce': 'foobar',
            'aud': 'aud'
        }).encode('utf-8')
        id_token = 'my_token'
        with self.assertRaisesMessage(SuspiciousOperation, 'JWT Nonce verification failed.'):
            self.backend.verify_token(id_token, **{'nonce': 'foo'})

    @override_settings(OIDC_CREATE_USER=False)
    @override_settings(OIDC_USE_NONCE=False)
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws')
    @patch('mozilla_django_oidc.auth.requests')
    def test_create_user_disabled(self, request_mock, jws_mock):
        """Test with user creation disabled and no user found."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        jws_mock.return_value = json.dumps({
            'nonce': 'nonce'
        }).encode('utf-8')
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
        self.assertEqual(self.backend.authenticate(request=auth_request), None)

    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws')
    @patch('mozilla_django_oidc.auth.requests')
    @override_settings(OIDC_USE_NONCE=False)
    def test_create_user_enabled(self, request_mock, jws_mock):
        """Test with user creation enabled and no user found."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        self.assertEqual(User.objects.filter(email='email@example.com').exists(), False)
        jws_mock.return_value = json.dumps({
            'nonce': 'nonce'
        }).encode('utf-8')
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
        self.assertEqual(self.backend.authenticate(request=auth_request),
                         User.objects.get(email='email@example.com'))

    @patch.object(settings, 'OIDC_USERNAME_ALGO')
    @override_settings(OIDC_USE_NONCE=False)
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws')
    @patch('mozilla_django_oidc.auth.requests')
    def test_custom_username_algo(self, request_mock, jws_mock, algo_mock):
        """Test user creation with custom username algorithm."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        self.assertEqual(User.objects.filter(email='email@example.com').exists(), False)
        algo_mock.return_value = 'username_algo'
        jws_mock.return_value = json.dumps({
            'nonce': 'nonce'
        }).encode('utf-8')
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
        self.assertEqual(self.backend.authenticate(request=auth_request),
                         User.objects.get(username='username_algo'))

    @override_settings(OIDC_USE_NONCE=False,
                       OIDC_USERNAME_ALGO='tests.test_auth.dotted_username_algo_callback')
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws')
    @patch('mozilla_django_oidc.auth.requests')
    def test_custom_username_algo_dotted_path(self, request_mock, jws_mock):
        """Test user creation with custom username algorithm with a dotted path."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        self.assertEqual(User.objects.filter(email='email@example.com').exists(), False)
        jws_mock.return_value = json.dumps({
            'nonce': 'nonce'
        }).encode('utf-8')
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
        self.assertEqual(self.backend.authenticate(request=auth_request),
                         User.objects.get(username='dotted_username_algo'))

    @override_settings(OIDC_USE_NONCE=False)
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws')
    @patch('mozilla_django_oidc.auth.requests')
    def test_duplicate_emails_exact(self, request_mock, jws_mock):
        """Test auth with two users having the same email."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        User.objects.create(username='user1', email='email@example.com')
        User.objects.create(username='user2', email='email@example.com')
        jws_mock.return_value = json.dumps({
            'nonce': 'nonce'
        }).encode('utf-8')
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
        self.assertEqual(self.backend.authenticate(request=auth_request), None)

    @override_settings(OIDC_USE_NONCE=False)
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws')
    @patch('mozilla_django_oidc.auth.requests')
    def test_duplicate_emails_case_mismatch(self, request_mock, jws_mock):
        """Test auth with two users having the same email, with different case."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        User.objects.create(username='user1', email='email@example.com')
        User.objects.create(username='user2', email='eMaIl@ExAmPlE.cOm')
        jws_mock.return_value = json.dumps({
            'nonce': 'nonce'
        }).encode('utf-8')
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
        self.assertEqual(self.backend.authenticate(request=auth_request), None)


class OIDCAuthenticationBackendRS256WithKeyTestCase(TestCase):
    """Authentication tests with ALG RS256 and provided IdP Sign Key."""

    @override_settings(OIDC_OP_TOKEN_ENDPOINT='https://server.example.com/token')
    @override_settings(OIDC_OP_USER_ENDPOINT='https://server.example.com/user')
    @override_settings(OIDC_RP_CLIENT_ID='example_id')
    @override_settings(OIDC_RP_CLIENT_SECRET='client_secret')
    @override_settings(OIDC_RP_SIGN_ALGO='RS256')
    @override_settings(OIDC_RP_IDP_SIGN_KEY='sign_key')
    def setUp(self):
        self.backend = OIDCAuthenticationBackend()

    @override_settings(OIDC_USE_NONCE=False)
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws')
    @patch('mozilla_django_oidc.auth.requests')
    def test_jwt_verify_sign_key(self, request_mock, jws_mock):
        """Test jwt verification signature."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        jws_mock.return_value = json.dumps({
            'aud': 'audience'
        }).encode('utf-8')
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
        self.backend.authenticate(request=auth_request)
        calls = [
            call(force_bytes('token'), 'sign_key')
        ]
        jws_mock.assert_has_calls(calls)


class OIDCAuthenticationBackendRS256WithJwksEndpointTestCase(TestCase):
    """Authentication tests with ALG RS256 and IpD JWKS Endpoint."""

    @override_settings(OIDC_OP_TOKEN_ENDPOINT='https://server.example.com/token')
    @override_settings(OIDC_OP_USER_ENDPOINT='https://server.example.com/user')
    @override_settings(OIDC_RP_CLIENT_ID='example_id')
    @override_settings(OIDC_RP_CLIENT_SECRET='client_secret')
    @override_settings(OIDC_RP_SIGN_ALGO='RS256')
    @override_settings(OIDC_OP_JWKS_ENDPOINT='https://server.example.com/jwks')
    def setUp(self):
        self.backend = OIDCAuthenticationBackend()

    @override_settings(OIDC_USE_NONCE=False)
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws')
    @patch('mozilla_django_oidc.auth.OIDCAuthenticationBackend.retrieve_matching_jwk')
    @patch('mozilla_django_oidc.auth.requests')
    def test_jwt_verify_sign_key(self, request_mock, jwk_mock, jws_mock):
        """Test jwt verification signature."""
        auth_request = RequestFactory().get('/foo', {'code': 'foo',
                                                     'state': 'bar'})
        auth_request.session = {}

        jwk_mock_ret = {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "cc7d29c9cb3780741cc0876633c9107a0f33c289",
            "n": "20LvblCBaPicNV3-NnJuahqbpi-b8hFD",
            "e": "AQAB"
        }
        jwk_mock.return_value = jwk_mock_ret

        jws_mock.return_value = json.dumps({
            'aud': 'audience'
        }).encode('utf-8')
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
        self.backend.authenticate(request=auth_request)
        calls = [
            call(force_bytes('token'), jwk_mock_ret)
        ]
        jws_mock.assert_has_calls(calls)


def dotted_username_algo_callback(email):
    return 'dotted_username_algo'
