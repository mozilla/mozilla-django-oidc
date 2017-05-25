from mock import patch

import django
from django.conf.urls import url
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.test.client import ClientHandler

from mozilla_django_oidc.contrib.auth0.middleware import RefreshIDToken
from mozilla_django_oidc.urls import urlpatterns as orig_urlpatterns


User = get_user_model()


DJANGO_VERSION = tuple(django.VERSION[0:2])


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


# This adds a "home page" we can test against.
def fakeview(req):
    return HttpResponse('Win!')


urlpatterns = list(orig_urlpatterns) + [
    url(r'^mdo_fake_view/$', fakeview, name='mdo_fake_view')
]


def override_middleware(fun):
    classes = [
        'django.contrib.sessions.middleware.SessionMiddleware',
        'mozilla_django_oidc.contrib.auth0.middleware.RefreshIDToken',
    ]
    if DJANGO_VERSION >= (1, 10):
        return override_settings(MIDDLEWARE=classes)(fun)
    return override_settings(MIDDLEWARE_CLASSES=classes)(fun)


class UserifiedClientHandler(ClientHandler):
    """Enhances ClientHandler to "work" with users properly"""
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super(UserifiedClientHandler, self).__init__(*args, **kwargs)

    def get_response(self, req):
        req.user = self.user
        return super(UserifiedClientHandler, self).get_response(req)


class ClientWithUser(Client):
    """Enhances Client to "work" with users properly"""
    def __init__(self, enforce_csrf_checks=False, **defaults):
        # Start off with the AnonymousUser
        self.user = AnonymousUser()
        # Get this because we need to create a new UserifiedClientHandler later
        self.enforce_csrf_checks = enforce_csrf_checks
        super(ClientWithUser, self).__init__(**defaults)
        # Stomp on the ClientHandler with one that correctly makes request.user
        # the AnonymousUser
        self.handler = UserifiedClientHandler(enforce_csrf_checks, user=self.user)

    def login(self, **credentials):
        from django.contrib.auth import authenticate

        # Try to authenticate and throw an exception if that fails; also, this gets
        # the user instance that was authenticated with
        user = authenticate(**credentials)
        if not user:
            # Client lets you fail authentication without providing any helpful
            # messages; we throw an exception because silent failure is
            # unhelpful
            raise Exception('Unable to authenticate with %r' % credentials)

        ret = super(ClientWithUser, self).login(**credentials)
        if not ret:
            raise Exception('Login failed')

        # Stash the user object it used and rebuild the UserifiedClientHandler
        self.user = user
        self.handler = UserifiedClientHandler(self.enforce_csrf_checks, user=self.user)
        return ret


@override_settings(ROOT_URLCONF='tests.auth0_tests.test_middleware')
@override_middleware
class MiddlewareTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='example_username', password='password')
        cache.clear()

    def test_anonymous(self):
        client = ClientWithUser()
        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 200)

    @patch('mozilla_django_oidc.contrib.auth0.middleware.cache')
    def test_authenticated(self, mock_cache):
        client = ClientWithUser()
        client.login(username=self.user.username, password='password')
        session = client.session
        session['oidc_id_token'] = True
        session.save()

        mock_cache.get.return_value = True

        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 200)

    @patch('mozilla_django_oidc.views.auth.logout')
    @patch('mozilla_django_oidc.contrib.auth0.middleware.refresh_id_token')
    @patch('mozilla_django_oidc.contrib.auth0.middleware.cache')
    @override_settings(LOGOUT_REDIRECT_URL='/logout_url')
    def test_expired(self, mock_cache, mock_refresh, mock_logout):
        client = ClientWithUser()
        client.login(username=self.user.username, password='password')
        session = client.session
        session['oidc_id_token'] = True
        session.save()

        mock_cache.get.return_value = False
        mock_refresh.return_value = None

        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 302)

        if DJANGO_VERSION == (1, 8):
            expected = 'http://testserver/logout_url'
        else:
            expected = '/logout_url'
        self.assertEqual(resp.url, expected)
