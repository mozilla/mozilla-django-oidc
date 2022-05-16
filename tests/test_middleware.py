import json
import re
import time

from urllib.parse import parse_qs

from mock import Mock, patch

from django.urls import path
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_out
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.dispatch import receiver
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.test.client import ClientHandler

from mozilla_django_oidc.middleware import SessionRefresh, RefreshOIDCAccessToken
from mozilla_django_oidc.urls import urlpatterns as orig_urlpatterns


User = get_user_model()


@override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
@override_settings(OIDC_RP_CLIENT_ID='foo')
@override_settings(OIDC_RENEW_TOKEN_EXPIRY_SECONDS=120)
@patch('mozilla_django_oidc.middleware.get_random_string')
class SessionRefreshTokenMiddlewareTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = SessionRefresh()
        self.user = User.objects.create_user('example_username')

    def test_anonymous(self, mock_middleware_random):
        request = self.factory.get('/foo')
        request.session = {}
        request.user = AnonymousUser()
        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    def test_is_oidc_path(self, mock_middleware_random):
        request = self.factory.get('/oidc/callback/')
        request.user = AnonymousUser()
        request.session = {}
        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    def test_is_POST(self, mock_middleware_random):
        request = self.factory.post('/foo')
        request.user = AnonymousUser()
        request.session = {}
        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    def test_is_ajax(self, mock_middleware_random):
        mock_middleware_random.return_value = 'examplestring'

        request = self.factory.get(
            '/foo',
            HTTP_X_REQUESTED_WITH='XMLHttpRequest'
        )
        request.session = {}
        request.user = self.user

        response = self.middleware.process_request(request)
        self.assertEqual(response.status_code, 403)
        # The URL to go to is available both as a header and as a key
        # in the JSON response.
        self.assertTrue(response['refresh_url'])
        url, qs = response['refresh_url'].split('?')
        self.assertEqual(url, 'http://example.com/authorize')
        expected_query = {
            'response_type': ['code'],
            'redirect_uri': ['http://testserver/callback/'],
            'client_id': ['foo'],
            'nonce': ['examplestring'],
            'prompt': ['none'],
            'scope': ['openid email'],
            'state': ['examplestring'],
        }
        self.assertEqual(expected_query, parse_qs(qs))
        json_payload = json.loads(response.content.decode('utf-8'))
        self.assertEqual(json_payload['refresh_url'], response['refresh_url'])

    def test_no_oidc_token_expiration_forces_renewal(self, mock_middleware_random):
        mock_middleware_random.return_value = 'examplestring'

        request = self.factory.get('/foo')
        request.user = self.user
        request.session = {}

        response = self.middleware.process_request(request)

        self.assertEqual(response.status_code, 302)
        url, qs = response.url.split('?')
        self.assertEqual(url, 'http://example.com/authorize')
        expected_query = {
            'response_type': ['code'],
            'redirect_uri': ['http://testserver/callback/'],
            'client_id': ['foo'],
            'nonce': ['examplestring'],
            'prompt': ['none'],
            'scope': ['openid email'],
            'state': ['examplestring'],
        }
        self.assertEqual(expected_query, parse_qs(qs))

    def test_expired_token_forces_renewal(self, mock_middleware_random):
        mock_middleware_random.return_value = 'examplestring'

        request = self.factory.get('/foo')
        request.user = self.user
        request.session = {
            'oidc_token_expiration': time.time() - 10
        }

        response = self.middleware.process_request(request)

        self.assertEqual(response.status_code, 302)
        url, qs = response.url.split('?')
        self.assertEqual(url, 'http://example.com/authorize')
        expected_query = {
            'response_type': ['code'],
            'redirect_uri': ['http://testserver/callback/'],
            'client_id': ['foo'],
            'nonce': ['examplestring'],
            'prompt': ['none'],
            'scope': ['openid email'],
            'state': ['examplestring'],
        }
        self.assertEqual(expected_query, parse_qs(qs))


@override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
@override_settings(OIDC_RP_CLIENT_ID='foo')
@override_settings(OIDC_RENEW_TOKEN_EXPIRY_SECONDS=120)
class RefreshOIDCAccessTokenMiddlewareTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = RefreshOIDCAccessToken()
        self.user = User.objects.create_user('example_username')

    def test_anonymous(self):
        request = self.factory.get('/foo')
        request.session = {}
        request.user = AnonymousUser()
        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    def test_is_oidc_path(self):
        request = self.factory.get('/oidc/callback/')
        request.user = AnonymousUser()
        request.session = {}
        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    def test_is_POST(self):
        request = self.factory.post('/foo')
        request.user = AnonymousUser()
        request.session = {}
        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    @override_settings(OIDC_OP_TOKEN_ENDPOINT='https://server.example.com/token')
    @override_settings(OIDC_RP_CLIENT_ID='foo')
    @override_settings(OIDC_RP_CLIENT_SECRET='client_secret')
    @override_settings(OIDC_RENEW_TOKEN_EXPIRY_SECONDS=120)
    @patch('mozilla_django_oidc.middleware.get_random_string')
    def test_no_refresh_token_expiration_forces_renewal(self, mock_random_string):
        mock_random_string.return_value = 'examplestring'

        request = self.factory.get('/foo')
        request.user = self.user
        request.session = {}

        response = self.middleware.process_request(request)

        self.assertEqual(response.status_code, 302)
        url, qs = response.url.split('?')
        self.assertEqual(url, 'http://example.com/authorize')
        expected_query = {
            'response_type': ['code'],
            'redirect_uri': ['http://testserver/callback/'],
            'client_id': ['foo'],
            'nonce': ['examplestring'],
            'prompt': ['none'],
            'scope': ['openid email'],
            'state': ['examplestring'],
        }
        self.assertEqual(expected_query, parse_qs(qs))


# This adds a "home page" we can test against.
def fakeview(req):
    return HttpResponse('Win!')


urlpatterns = list(orig_urlpatterns) + [
    path('mdo_fake_view/', fakeview, name='mdo_fake_view')
]


def override_middleware(middleware):
    def wrap(fun):
        classes = [
            'django.contrib.sessions.middleware.SessionMiddleware',
            middleware,
        ]
        return override_settings(MIDDLEWARE=classes)(fun)
    return wrap


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


@override_settings(OIDC_RP_CLIENT_ID='foo')
@override_settings(OIDC_RENEW_TOKEN_EXPIRY_SECONDS=120)
@override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
@override_settings(ROOT_URLCONF='tests.test_middleware')
@override_middleware('mozilla_django_oidc.middleware.SessionRefresh')
class SessionRefreshMiddlewareTestCase(TestCase):
    """These tests test the middleware as part of the request/response cycle"""
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='example_username', password='password')
        cache.clear()

    @override_settings(OIDC_EXEMPT_URLS=['mdo_fake_view'])
    def test_get_exempt_urls_setting_view_name(self):
        middleware = SessionRefresh()
        self.assertEqual(
            sorted(list(middleware.exempt_urls)),
            [u'/authenticate/', u'/callback/', u'/logout/', u'/mdo_fake_view/']
        )

    @override_settings(OIDC_EXEMPT_URLS=['/foo/'])
    def test_get_exempt_urls_setting_url_path(self):
        middleware = SessionRefresh()
        self.assertEqual(
            sorted(list(middleware.exempt_urls)),
            [u'/authenticate/', u'/callback/', u'/foo/', u'/logout/']
        )

    def test_is_refreshable_url(self):
        request = self.factory.get('/mdo_fake_view/')
        request.user = self.user
        request.session = dict()
        middleware = SessionRefresh()
        assert middleware.is_refreshable_url(request)

    @override_settings(OIDC_EXEMPT_URLS=['mdo_fake_view'])
    def test_is_not_refreshable_url_exempt_view_name(self):
        request = self.factory.get('/mdo_fake_view/')
        request.user = self.user
        request.session = dict()
        middleware = SessionRefresh()
        assert not middleware.is_refreshable_url(request)

    @override_settings(OIDC_EXEMPT_URLS=['/mdo_fake_view/'])
    def test_is_not_refreshable_url_exempt_path(self):
        request = self.factory.get('/mdo_fake_view/')
        request.user = self.user
        request.session = dict()
        middleware = SessionRefresh()
        assert not middleware.is_refreshable_url(request)

    @override_settings(OIDC_EXEMPT_URLS=[re.compile(r'^/mdo_.*_view/$')])
    def test_is_not_refreshable_url_exempt_pattern(self):
        request = self.factory.get('/mdo_fake_view/')
        request.user = self.user
        request.session = dict()
        middleware = SessionRefresh()
        assert not middleware.is_refreshable_url(request)

    def test_anonymous(self):
        client = ClientWithUser()
        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 200)

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
    @override_settings(OIDC_RP_CLIENT_ID='foo')
    @override_settings(OIDC_RENEW_TOKEN_EXPIRY_SECONDS=120)
    def test_authenticated_user(self):
        client = ClientWithUser()
        client.login(username=self.user.username, password='password')

        # Set the expiration to some time in the future so this user is valid
        session = client.session
        session['oidc_token_expiration'] = time.time() + 100
        session.save()

        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 200)

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
    @override_settings(OIDC_RP_CLIENT_ID='foo')
    @override_settings(OIDC_RENEW_TOKEN_EXPIRY_SECONDS=120)
    @patch('mozilla_django_oidc.middleware.get_random_string')
    def test_expired_token_redirects_to_sso(self, mock_middleware_random):
        mock_middleware_random.return_value = 'examplestring'

        client = ClientWithUser()
        client.login(username=self.user.username, password='password')

        # Set expiration to some time in the past
        session = client.session
        session['oidc_token_expiration'] = time.time() - 100
        session['_auth_user_backend'] = 'mozilla_django_oidc.auth.OIDCAuthenticationBackend'
        session.save()

        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 302)

        url, qs = resp.url.split('?')
        self.assertEqual(url, 'http://example.com/authorize')
        expected_query = {
            'response_type': ['code'],
            'redirect_uri': ['http://testserver/callback/'],
            'client_id': ['foo'],
            'nonce': ['examplestring'],
            'prompt': ['none'],
            'scope': ['openid email'],
            'state': ['examplestring'],
        }
        self.assertEqual(expected_query, parse_qs(qs))

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
    @override_settings(OIDC_RP_CLIENT_ID='foo')
    @override_settings(OIDC_RENEW_TOKEN_EXPIRY_SECONDS=120)
    @patch('mozilla_django_oidc.middleware.get_random_string')
    def test_refresh_fails_for_already_signed_in_user(self, mock_random_string):
        mock_random_string.return_value = 'examplestring'

        # Mutable to log which users get logged out.
        logged_out_users = []

        # Register a signal on 'user_logged_out' so we can
        # update 'logged_out_users'.
        @receiver(user_logged_out)
        def logged_out(sender, user=None, **kwargs):
            logged_out_users.append(user)

        client = ClientWithUser()
        # First confirm that the home page is a public page.
        resp = client.get('/')
        # At least security doesn't kick you out.
        self.assertEqual(resp.status_code, 404)
        # Also check that this page doesn't force you to redirect
        # to authenticate.
        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 200)
        client.login(username=self.user.username, password='password')

        # Set expiration to some time in the past
        session = client.session
        session['oidc_token_expiration'] = time.time() - 100
        session['_auth_user_backend'] = 'mozilla_django_oidc.auth.OIDCAuthenticationBackend'
        session.save()

        # Confirm that now you're forced to authenticate again.
        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(
            'http://example.com/authorize' in resp.url and
            'prompt=none' in resp.url
        )
        # Now suppose the user goes there and something goes wrong.
        # For example, the user might have become "blocked" or the 2FA
        # verficiation has expired and needs to be done again.
        resp = client.get('/callback/', {
            'error': 'login_required',
            'error_description': 'Multifactor authentication required',
        })
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, '/')

        # Since the user in 'client' doesn't change, we have to use other
        # queues to assert that the user got logged out properly.

        # The session gets flushed when you get signed out.
        # This is the only decent way to know the user lost all
        # request.session and
        self.assertTrue(not client.session.items())

        # The signal we registered should have fired for this user.
        self.assertEqual(client.user, logged_out_users[0])


@override_settings(ROOT_URLCONF='tests.test_middleware')
@override_middleware('mozilla_django_oidc.middleware.RefreshOIDCAccessToken')
class RefreshOIDCAccessTokenTestCase(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(username='example_username', password='password')
        cache.clear()

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
    @override_settings(OIDC_OP_TOKEN_ENDPOINT='https://server.example.com/token')
    @override_settings(OIDC_RP_CLIENT_ID='foo')
    @override_settings(OIDC_RP_CLIENT_SECRET='client_secret')
    @override_settings(OIDC_RENEW_TOKEN_EXPIRY_SECONDS=120)
    @override_settings(OIDC_STORE_REFRESH_TOKEN=True)
    @patch('mozilla_django_oidc.middleware.get_random_string')
    @patch('mozilla_django_oidc.middleware.requests')
    def test_refresh_token_forces_renewal(self, request_mock, mock_random_string):
        mock_random_string.return_value = 'examplestring'

        post_json_mock = Mock()
        post_json_mock.json.return_value = {
            'id_token': 'id_token',
            'accesss_token': 'access_token',
            'refresh_token': 'new_refresh_token'
        }
        request_mock.post.return_value = post_json_mock

        client = ClientWithUser()
        # First confirm that the home page is a public page.
        resp = client.get('/')
        # At least security doesn't kick you out.
        self.assertEqual(resp.status_code, 404)
        # Also check that this page doesn't force you to redirect
        # to authenticate.
        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 200)
        client.login(username=self.user.username, password='password')

        # Set expiration to some time in the past
        session = client.session
        session['oidc_token_expiration'] = time.time() - 100
        session['oidc_refresh_token'] = 'examplerefreshtoken'
        session['_auth_user_backend'] = 'mozilla_django_oidc.auth.OIDCAuthenticationBackend'
        session.save()

        # Confirm that the session value has been refreshed.
        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(client.session['oidc_refresh_token'], 'new_refresh_token')
