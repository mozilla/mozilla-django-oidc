import json
import time

try:
    from urllib.parse import parse_qs
except ImportError:
    # Python < 3
    from urlparse import parse_qs

from mock import patch

import django
from django.conf.urls import url
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.test.client import ClientHandler

from mozilla_django_oidc.middleware import RefreshIDToken
from mozilla_django_oidc.urls import urlpatterns as orig_urlpatterns


User = get_user_model()


DJANGO_VERSION = tuple(django.VERSION[0:2])


class RefreshIDTokenMiddlewareTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = RefreshIDToken()
        self.user = User.objects.create_user('example_username')

    def test_anonymous(self):
        request = self.factory.get('/foo')
        request.user = AnonymousUser()
        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    def test_is_oidc_path(self):
        request = self.factory.get('/oidc/callback/')
        request.user = AnonymousUser()
        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    def test_is_POST(self):
        request = self.factory.post('/foo')
        request.user = AnonymousUser()
        response = self.middleware.process_request(request)
        self.assertTrue(not response)

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
    @override_settings(OIDC_RP_CLIENT_ID='foo')
    @override_settings(OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS=120)
    @patch('mozilla_django_oidc.middleware.get_random_string')
    def test_is_ajax(self, mock_random_string):
        mock_random_string.return_value = 'examplestring'

        request = self.factory.get(
            '/foo',
            HTTP_X_REQUESTED_WITH='XMLHttpRequest'
        )
        request.session = {}
        request.user = self.user

        response = self.middleware.process_request(request)
        self.assertEquals(response.status_code, 403)
        # The URL to go to is available both as a header and as a key
        # in the JSON response.
        self.assertTrue(response['refresh_url'])
        url, qs = response['refresh_url'].split('?')
        self.assertEquals(url, 'http://example.com/authorize')
        expected_query = {
            'response_type': ['code'],
            'redirect_uri': ['http://testserver/callback/'],
            'client_id': ['foo'],
            'nonce': ['examplestring'],
            'prompt': ['none'],
            'scope': ['openid email'],
            'state': ['examplestring'],
        }
        self.assertEquals(expected_query, parse_qs(qs))
        json_payload = json.loads(response.content.decode('utf-8'))
        self.assertEquals(json_payload['refresh_url'], response['refresh_url'])

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
    @override_settings(OIDC_RP_CLIENT_ID='foo')
    @override_settings(OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS=120)
    @patch('mozilla_django_oidc.middleware.get_random_string')
    def test_no_oidc_token_expiration_forces_renewal(self, mock_random_string):
        mock_random_string.return_value = 'examplestring'

        request = self.factory.get('/foo')
        request.user = self.user
        request.session = {}

        response = self.middleware.process_request(request)

        self.assertEquals(response.status_code, 302)
        url, qs = response.url.split('?')
        self.assertEquals(url, 'http://example.com/authorize')
        expected_query = {
            'response_type': ['code'],
            'redirect_uri': ['http://testserver/callback/'],
            'client_id': ['foo'],
            'nonce': ['examplestring'],
            'prompt': ['none'],
            'scope': ['openid email'],
            'state': ['examplestring'],
        }
        self.assertEquals(expected_query, parse_qs(qs))

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
    @override_settings(OIDC_RP_CLIENT_ID='foo')
    @override_settings(OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS=120)
    @patch('mozilla_django_oidc.middleware.get_random_string')
    def test_expired_token_forces_renewal(self, mock_random_string):
        mock_random_string.return_value = 'examplestring'

        request = self.factory.get('/foo')
        request.user = self.user
        request.session = {
            'oidc_id_token_expiration': time.time() - 10
        }

        response = self.middleware.process_request(request)

        self.assertEquals(response.status_code, 302)
        url, qs = response.url.split('?')
        self.assertEquals(url, 'http://example.com/authorize')
        expected_query = {
            'response_type': ['code'],
            'redirect_uri': ['http://testserver/callback/'],
            'client_id': ['foo'],
            'nonce': ['examplestring'],
            'prompt': ['none'],
            'scope': ['openid email'],
            'state': ['examplestring'],
        }
        self.assertEquals(expected_query, parse_qs(qs))


# This adds a "home page" we can test against.
def fakeview(req):
    return HttpResponse('Win!')


urlpatterns = list(orig_urlpatterns) + [
    url(r'^mdo_fake_view/$', fakeview, name='mdo_fake_view')
]


def override_middleware(fun):
    classes = [
        'django.contrib.sessions.middleware.SessionMiddleware',
        'mozilla_django_oidc.middleware.RefreshIDToken',
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


@override_settings(ROOT_URLCONF='tests.test_middleware')
@override_middleware
class MiddlewareTestCase(TestCase):
    """These tests test the middleware as part of the request/response cycle"""
    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(username='example_username', password='password')
        cache.clear()

    @override_settings(OIDC_EXEMPT_URLS=['mdo_fake_view'])
    def test_get_exempt_urls_setting_view_name(self):
        middleware = RefreshIDToken()
        self.assertEquals(
            sorted(list(middleware.exempt_urls)),
            [u'/authenticate/', u'/callback/', u'/logout/', u'/mdo_fake_view/']
        )

    @override_settings(OIDC_EXEMPT_URLS=['/foo/'])
    def test_get_exempt_urls_setting_url_path(self):
        middleware = RefreshIDToken()
        self.assertEquals(
            sorted(list(middleware.exempt_urls)),
            [u'/authenticate/', u'/callback/', u'/foo/', u'/logout/']
        )

    def test_anonymous(self):
        client = ClientWithUser()
        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 200)

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
    @override_settings(OIDC_RP_CLIENT_ID='foo')
    @override_settings(OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS=120)
    def test_authenticated_user(self):
        client = ClientWithUser()
        client.login(username=self.user.username, password='password')

        # Set the expiration to some time in the future so this user is valid
        session = client.session
        session['oidc_id_token_expiration'] = time.time() + 100
        session.save()

        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 200)

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT='http://example.com/authorize')
    @override_settings(OIDC_RP_CLIENT_ID='foo')
    @override_settings(OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS=120)
    @patch('mozilla_django_oidc.middleware.get_random_string')
    def test_expired_token_redirects_to_sso(self, mock_random_string):
        mock_random_string.return_value = 'examplestring'

        client = ClientWithUser()
        client.login(username=self.user.username, password='password')

        # Set expiration to some time in the past
        session = client.session
        session['oidc_id_token_expiration'] = time.time() - 100
        session.save()

        resp = client.get('/mdo_fake_view/')
        self.assertEqual(resp.status_code, 302)

        url, qs = resp.url.split('?')
        self.assertEquals(url, 'http://example.com/authorize')
        expected_query = {
            'response_type': ['code'],
            'redirect_uri': ['http://testserver/callback/'],
            'client_id': ['foo'],
            'nonce': ['examplestring'],
            'prompt': ['none'],
            'scope': ['openid email'],
            'state': ['examplestring'],
        }
        self.assertEquals(expected_query, parse_qs(qs))
