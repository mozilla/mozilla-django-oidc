from mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase, override_settings

from mozilla_django_oidc.contrib.auth0.middleware import RefreshIDToken


User = get_user_model()


class RefreshIDTokenTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = RefreshIDToken()
        self.user = User.objects.create_user('example_username')

    def test_anonymous(self):
        request = self.factory.get('/foo')
        request.user = AnonymousUser()
        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    def test_is_ajax(self):
        request = self.factory.get(
            '/foo',
            HTTP_X_REQUESTED_WITH='XMLHttpRequest'
        )
        request.user = self.user

        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    def test_user_token_not_in_session(self):
        request = self.factory.get('/foo')
        request.user = self.user
        request.session = {}

        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    @patch('mozilla_django_oidc.contrib.auth0.middleware.cache')
    def test_user_token_in_session(self, mock_cache):
        request = self.factory.get('/foo')
        request.user = self.user
        request.session = {
            'oidc_id_token': 'foobar'
        }
        mock_cache.get.return_value = True
        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    @patch('mozilla_django_oidc.contrib.auth0.middleware.refresh_id_token')
    @patch('mozilla_django_oidc.contrib.auth0.middleware.cache')
    @override_settings(OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS=120)
    def test_stale_cache_valid_token(self, mock_cache, mock_refresh):
        request = self.factory.get('/foo')
        request.user = self.user
        request.session = {
            'oidc_id_token': 'foobar'
        }
        mock_cache.get.return_value = False
        mock_refresh.return_value = 'renewed_token'
        response = self.middleware.process_request(request)
        self.assertTrue(not response)
        cache_key = 'renew_id_token:{}'.format(self.user.id)
        mock_refresh.assert_called_once_with('foobar')
        mock_cache.set.assert_called_once_with(cache_key, True, 120)

    @patch('mozilla_django_oidc.views.auth.logout')
    @patch('mozilla_django_oidc.contrib.auth0.middleware.refresh_id_token')
    @patch('mozilla_django_oidc.contrib.auth0.middleware.cache')
    @override_settings(LOGOUT_REDIRECT_URL='/logout_url')
    @override_settings(OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS=120)
    def test_stale_cache_invalid_token(self, mock_cache, mock_refresh, mock_logout):
        request = self.factory.get('/foo')
        request.user = self.user
        request.session = {
            'oidc_id_token': 'foobar'
        }
        mock_cache.get.return_value = False
        mock_refresh.return_value = None
        response = self.middleware.process_request(request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/logout_url')
        mock_refresh.assert_called_once_with('foobar')
        mock_logout.assert_called_once_with(request)
