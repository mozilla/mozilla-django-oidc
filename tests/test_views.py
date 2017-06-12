try:
    from urlparse import parse_qs, urlparse
except ImportError:
    from urllib.parse import parse_qs, urlparse

from mock import patch

from django.core.exceptions import SuspiciousOperation
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.urlresolvers import reverse
from django.test import RequestFactory, TestCase, override_settings

from mozilla_django_oidc import views


User = get_user_model()


def my_custom_op_logout(*args, **kwargs):
    return 'http://example.com/logged/out'


class OIDCAuthorizationCallbackViewTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(LOGIN_REDIRECT_URL='/success')
    def test_get_auth_success(self):
        """Test successful callback request to RP."""
        user = User.objects.create_user('example_username')

        get_data = {
            'code': 'example_code',
            'state': 'example_state'
        }
        url = reverse('oidc_authentication_callback')
        request = self.factory.get(url, get_data)
        request.session = {
            'oidc_state': 'example_state'
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch('mozilla_django_oidc.views.auth.authenticate') as mock_auth:
            with patch('mozilla_django_oidc.views.auth.login') as mock_login:
                mock_auth.return_value = user
                response = callback_view(request)

                mock_auth.assert_called_once_with(nonce=None,
                                                  request=request)
                mock_login.assert_called_once_with(request, user)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/success')

    @override_settings(LOGIN_REDIRECT_URL='/success')
    def test_get_auth_success_next_url(self):
        """Test successful callback request to RP with custom `next` url."""
        user = User.objects.create_user('example_username')

        get_data = {
            'code': 'example_code',
            'state': 'example_state'
        }
        url = reverse('oidc_authentication_callback')
        request = self.factory.get(url, get_data)
        request.session = {
            'oidc_state': 'example_state',
            'oidc_login_next': '/foobar'
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch('mozilla_django_oidc.views.auth.authenticate') as mock_auth:
            with patch('mozilla_django_oidc.views.auth.login') as mock_login:
                mock_auth.return_value = user
                response = callback_view(request)

                mock_auth.assert_called_once_with(nonce=None,
                                                  request=request)
                mock_login.assert_called_once_with(request, user)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/foobar')

    @override_settings(LOGIN_REDIRECT_URL_FAILURE='/failure')
    def test_get_auth_failure_nonexisting_user(self):
        """Test unsuccessful authentication and redirect url."""
        get_data = {
            'code': 'example_code',
            'state': 'example_state'
        }

        url = reverse('oidc_authentication_callback')
        request = self.factory.get(url, get_data)
        request.session = {
            'oidc_state': 'example_state'
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch('mozilla_django_oidc.views.auth.authenticate') as mock_auth:
            mock_auth.return_value = None
            response = callback_view(request)

            mock_auth.assert_called_once_with(nonce=None,
                                              request=request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/failure')

    @override_settings(LOGIN_REDIRECT_URL_FAILURE='/failure')
    def test_get_auth_failure_inactive_user(self):
        """Test authentication failure attempt for an inactive user."""
        user = User.objects.create_user('example_username')
        user.is_active = False
        user.save()

        get_data = {
            'code': 'example_code',
            'state': 'example_state'
        }

        url = reverse('oidc_authentication_callback')
        request = self.factory.get(url, get_data)
        request.session = {
            'oidc_state': 'example_state'
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch('mozilla_django_oidc.views.auth.authenticate') as mock_auth:
            mock_auth.return_value = user
            response = callback_view(request)

            mock_auth.assert_called_once_with(request=request,
                                              nonce=None)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/failure')

    @override_settings(OIDC_USE_NONCE=False)
    @override_settings(LOGIN_REDIRECT_URL_FAILURE='/failure')
    def test_get_auth_dirty_data(self):
        """Test authentication attempt with wrong get data."""
        get_data = {
            'foo': 'bar',
        }

        url = reverse('oidc_authentication_callback')
        request = self.factory.get(url, get_data)
        request.session = {}
        callback_view = views.OIDCAuthenticationCallbackView.as_view()
        response = callback_view(request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/failure')

    @override_settings(LOGIN_REDIRECT_URL_FAILURE='/failure')
    def test_get_auth_failure_missing_session_state(self):
        """Test authentication failure attempt for an inactive user."""
        user = User.objects.create_user('example_username')
        user.is_active = False
        user.save()

        get_data = {
            'code': 'example_code',
            'state': 'example_state'
        }

        url = reverse('oidc_authentication_callback')
        request = self.factory.get(url, get_data)
        request.session = {
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        response = callback_view(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/failure')

    @override_settings(LOGIN_REDIRECT_URL_FAILURE='/failure')
    def test_get_auth_failure_tampered_session_state(self):
        """Test authentication failure attempt for an inactive user."""
        user = User.objects.create_user('example_username')
        user.is_active = False
        user.save()

        get_data = {
            'code': 'example_code',
            'state': 'example_state'
        }

        url = reverse('oidc_authentication_callback')
        request = self.factory.get(url, get_data)
        request.session = {
            'oidc_state': 'tampered_state'
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with self.assertRaises(SuspiciousOperation) as context:
            callback_view(request)

        expected_error_message = 'Session `oidc_state` does not match the OIDC callback state'
        self.assertEqual(context.exception.args, (expected_error_message,))

    @override_settings(LOGIN_REDIRECT_URL='/success')
    def test_nonce_is_deleted(self):
        """Test Nonce is not in session."""
        user = User.objects.create_user('example_username')

        get_data = {
            'code': 'example_code',
            'state': 'example_state'
        }
        url = reverse('oidc_authentication_callback')
        request = self.factory.get(url, get_data)
        request.session = {
            'oidc_state': 'example_state',
            'oidc_nonce': 'example_nonce'
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch('mozilla_django_oidc.views.auth.authenticate') as mock_auth:
            with patch('mozilla_django_oidc.views.auth.login') as mock_login:
                mock_auth.return_value = user
                response = callback_view(request)

                mock_auth.assert_called_once_with(nonce='example_nonce',
                                                  request=request)
                mock_login.assert_called_once_with(request, user)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/success')
        self.assertTrue('oidc_nonce' not in request.session)


class OIDCAuthorizationRequestViewTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='https://server.example.com/auth')
    @override_settings(OIDC_RP_CLIENT_ID='example_id')
    @override_settings(SITE_URL='http://site-url.com')
    @patch('mozilla_django_oidc.views.get_random_string')
    def test_get(self, mock_random_string):
        """Test initiation of a successful OIDC attempt."""
        mock_random_string.return_value = 'examplestring'
        url = reverse('oidc_authentication_init')
        request = self.factory.get(url)
        request.session = dict()
        login_view = views.OIDCAuthenticationRequestView.as_view()
        response = login_view(request)
        self.assertEqual(response.status_code, 302)

        o = urlparse(response.url)
        expected_query = {
            'response_type': ['code'],
            'scope': ['openid'],
            'client_id': ['example_id'],
            'redirect_uri': ['http://site-url.com/callback/'],
            'state': ['examplestring'],
            'nonce': ['examplestring']
        }
        self.assertDictEqual(parse_qs(o.query), expected_query)
        self.assertEqual(o.hostname, 'server.example.com')
        self.assertEqual(o.path, '/auth')

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='https://server.example.com/auth')
    @override_settings(OIDC_RP_CLIENT_ID='example_id')
    def test_next_url(self):
        """Test that `next` url gets stored to user session."""
        url = reverse('oidc_authentication_init')
        request = self.factory.get('{url}?{params}'.format(url=url, params='next=/foo'))
        request.session = dict()
        login_view = views.OIDCAuthenticationRequestView.as_view()
        login_view(request)
        self.assertTrue('oidc_login_next' in request.session)
        self.assertEqual(request.session['oidc_login_next'], '/foo')

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='https://server.example.com/auth')
    @override_settings(OIDC_RP_CLIENT_ID='example_id')
    def test_missing_next_url(self):
        """Test that `next` url gets invalidated in user session."""
        url = reverse('oidc_authentication_init')
        request = self.factory.get(url)
        request.session = {
            'oidc_login_next': 'foobar'
        }
        login_view = views.OIDCAuthenticationRequestView.as_view()
        login_view(request)
        self.assertTrue('oidc_login_next' in request.session)
        self.assertTrue(request.session['oidc_login_next'] is None)


class OIDCLogoutViewTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(LOGOUT_REDIRECT_URL='/example-logout')
    def test_get_anonymous_user(self):
        url = reverse('oidc_logout')
        request = self.factory.post(url)
        request.user = AnonymousUser()
        logout_view = views.OIDCLogoutView.as_view()

        response = logout_view(request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/example-logout')

    @override_settings(LOGOUT_REDIRECT_URL='/example-logout')
    def test_post(self):
        user = User.objects.create_user('example_username')
        url = reverse('oidc_logout')
        request = self.factory.post(url)
        request.user = user
        logout_view = views.OIDCLogoutView.as_view()

        with patch('mozilla_django_oidc.views.auth.logout') as mock_logout:
            response = logout_view(request)
            mock_logout.assert_called_once_with(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/example-logout')

    @override_settings(LOGOUT_REDIRECT_URL='/example-logout')
    @override_settings(OIDC_OP_LOGOUT_URL_METHOD='tests.test_views.my_custom_op_logout')
    def test_post_with_OIDC_OP_LOGOUT_URL_METHOD(self):
        user = User.objects.create_user('example_username')
        url = reverse('oidc_logout')
        request = self.factory.post(url)
        request.user = user
        logout_view = views.OIDCLogoutView.as_view()

        with patch('mozilla_django_oidc.views.auth.logout') as mock_logout:
            response = logout_view(request)
            mock_logout.assert_called_once_with(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, 'http://example.com/logged/out')
