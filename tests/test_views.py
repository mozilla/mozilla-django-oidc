import time
from urllib.parse import parse_qs, urlparse

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import SuspiciousOperation
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse
from unittest.mock import patch

from mozilla_django_oidc import views

TEST_CODE_VERIFIER = "ThisStringIsURLSafeAndAtLeast43Characters00"


User = get_user_model()


def my_custom_op_logout(request):
    return request.build_absolute_uri("/logged/out")


class OIDCAuthorizationCallbackViewTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(LOGIN_REDIRECT_URL="/success")
    def test_get_auth_success(self):
        """Test successful callback request to RP."""
        user = User.objects.create_user("example_username")

        get_data = {"code": "example_code", "state": "example_state"}
        url = reverse("oidc_authentication_callback")
        request = self.factory.get(url, get_data)
        client = Client()
        request.session = client.session
        request.session["oidc_states"] = {
            "example_state": {
                "code_verifier": TEST_CODE_VERIFIER,
                "nonce": None,
                "added_on": time.time(),
            },
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch("mozilla_django_oidc.views.auth.authenticate") as mock_auth:
            with patch("mozilla_django_oidc.views.auth.login") as mock_login:
                mock_auth.return_value = user
                response = callback_view(request)

                mock_auth.assert_called_once_with(
                    code_verifier=TEST_CODE_VERIFIER, nonce=None, request=request
                )
                mock_login.assert_called_once_with(request, user)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/success")

    @override_settings(LOGIN_REDIRECT_URL="/success")
    def test_get_auth_success_next_url(self):
        """Test successful callback request to RP with custom `next` url."""
        user = User.objects.create_user("example_username")

        get_data = {"code": "example_code", "state": "example_state"}
        url = reverse("oidc_authentication_callback")
        request = self.factory.get(url, get_data)
        client = Client()
        request.session = client.session
        request.session["oidc_states"] = {
            "example_state": {
                "code_verifier": TEST_CODE_VERIFIER,
                "nonce": None,
                "added_on": time.time(),
            },
        }
        request.session["oidc_login_next"] = "/foobar"
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch("mozilla_django_oidc.views.auth.authenticate") as mock_auth:
            with patch("mozilla_django_oidc.views.auth.login") as mock_login:
                mock_auth.return_value = user
                response = callback_view(request)

                mock_auth.assert_called_once_with(
                    code_verifier=TEST_CODE_VERIFIER, nonce=None, request=request
                )
                mock_login.assert_called_once_with(request, user)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/foobar")

    @override_settings(LOGIN_REDIRECT_URL="/success")
    def test_get_auth_success_without_pkce(self):
        """Test successful callback request to RP after disabling PKCE."""
        user = User.objects.create_user("example_username")

        get_data = {"code": "example_code", "state": "example_state"}
        url = reverse("oidc_authentication_callback")
        request = self.factory.get(url, get_data)
        client = Client()
        request.session = client.session
        request.session["oidc_states"] = {
            "example_state": {
                # Simulates an auth request sent with PKCE disabled
                # 'code_verifier': TEST_CODE_VERIFIER,
                "nonce": None,
                "added_on": time.time(),
            },
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch("mozilla_django_oidc.views.auth.authenticate") as mock_auth:
            with patch("mozilla_django_oidc.views.auth.login") as mock_login:
                mock_auth.return_value = user
                response = callback_view(request)

                mock_auth.assert_called_once_with(
                    code_verifier=None, nonce=None, request=request
                )
                mock_login.assert_called_once_with(request, user)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/success")

    @override_settings(LOGIN_REDIRECT_URL_FAILURE="/failure")
    def test_get_auth_failure_nonexisting_user(self):
        """Test unsuccessful authentication and redirect url."""
        get_data = {"code": "example_code", "state": "example_state"}

        url = reverse("oidc_authentication_callback")
        request = self.factory.get(url, get_data)
        client = Client()
        request.session = client.session
        request.session["oidc_states"] = {
            "example_state": {"nonce": None, "added_on": time.time()},
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch("mozilla_django_oidc.views.auth.authenticate") as mock_auth:
            mock_auth.return_value = None
            response = callback_view(request)

            mock_auth.assert_called_once_with(
                code_verifier=None, nonce=None, request=request
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/failure")

    @override_settings(LOGIN_REDIRECT_URL_FAILURE="/failure")
    def test_get_auth_failure_inactive_user(self):
        """Test authentication failure attempt for an inactive user."""
        user = User.objects.create_user("example_username")
        user.is_active = False
        user.save()

        get_data = {"code": "example_code", "state": "example_state"}

        url = reverse("oidc_authentication_callback")
        request = self.factory.get(url, get_data)
        client = Client()
        request.session = client.session
        request.session["oidc_states"] = {
            "example_state": {"nonce": None, "added_on": time.time()},
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch("mozilla_django_oidc.views.auth.authenticate") as mock_auth:
            mock_auth.return_value = user
            response = callback_view(request)

            mock_auth.assert_called_once_with(
                code_verifier=None, request=request, nonce=None
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/failure")

    @override_settings(LOGIN_REDIRECT_URL_FAILURE="/failure")
    def test_get_auth_error(self):
        """Test authentication error handling.

        Sttate should be removed from session and user should be logged out.
        """
        user = User.objects.create_user("example_username")

        get_data = {"error": "example_code", "state": "example_state"}
        url = reverse("oidc_authentication_callback")
        request = self.factory.get(url, get_data)
        client = Client()
        request.session = client.session
        request.session["oidc_states"] = {
            "example_state": {"nonce": None, "added_on": time.time()},
        }
        request.user = user
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch("mozilla_django_oidc.views.auth.logout") as mock_logout:

            def clear_user(request):
                # Assert state is cleared prior to logout
                self.assertEqual(request.session["oidc_states"], {})
                request.user = AnonymousUser()

            mock_logout.side_effect = clear_user
            response = callback_view(request)
            mock_logout.assert_called_once()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/failure")

    @override_settings(OIDC_USE_NONCE=False)
    @override_settings(LOGIN_REDIRECT_URL_FAILURE="/failure")
    def test_get_auth_dirty_data(self):
        """Test authentication attempt with wrong get data."""
        get_data = {
            "foo": "bar",
        }

        url = reverse("oidc_authentication_callback")
        request = self.factory.get(url, get_data)
        request.session = {}
        callback_view = views.OIDCAuthenticationCallbackView.as_view()
        response = callback_view(request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/failure")

    @override_settings(LOGIN_REDIRECT_URL_FAILURE="/failure")
    def test_get_auth_failure_missing_session_state(self):
        """Test authentication failure attempt for an inactive user."""
        user = User.objects.create_user("example_username")
        user.is_active = False
        user.save()

        get_data = {"code": "example_code", "state": "example_state"}

        url = reverse("oidc_authentication_callback")
        request = self.factory.get(url, get_data)
        request.session = {}
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        response = callback_view(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/failure")

    @override_settings(LOGIN_REDIRECT_URL_FAILURE="/failure")
    def test_get_auth_failure_tampered_session_state(self):
        """Test authentication failure attempt for an inactive user."""
        user = User.objects.create_user("example_username")
        user.is_active = False
        user.save()

        get_data = {"code": "example_code", "state": "example_state"}

        url = reverse("oidc_authentication_callback")
        request = self.factory.get(url, get_data)
        request.session = {"oidc_states": {"tampered_state": None}}
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with self.assertRaises(SuspiciousOperation) as context:
            callback_view(request)

        expected_error_message = (
            "OIDC callback state not found in session `oidc_states`!"
        )
        self.assertEqual(context.exception.args, (expected_error_message,))

    @override_settings(LOGIN_REDIRECT_URL="/success")
    def test_nonce_is_deleted(self):
        """Test Nonce is not in session."""
        user = User.objects.create_user("example_username")

        get_data = {"code": "example_code", "state": "example_state"}
        url = reverse("oidc_authentication_callback")
        request = self.factory.get(url, get_data)
        client = Client()
        request.session = client.session
        request.session["oidc_states"] = {
            "example_state": {"nonce": "example_nonce", "added_on": time.time()},
        }
        request.session["oidc_nonce"] = "example_nonce"
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        with patch("mozilla_django_oidc.views.auth.authenticate") as mock_auth:
            with patch("mozilla_django_oidc.views.auth.login") as mock_login:
                mock_auth.return_value = user
                response = callback_view(request)

                mock_auth.assert_called_once_with(
                    code_verifier=None, nonce="example_nonce", request=request
                )
                mock_login.assert_called_once_with(request, user)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/success")
        self.assertTrue("example_state" not in request.session["oidc_states"])

    def test_multiple_login_sessions(self):
        """Test if states/nonces of other login sessions remain in the 'oidc_states' dictionary."""
        get_data = {"code": "example_code", "state": "example_state"}
        url = reverse("oidc_authentication_callback")
        request = self.factory.get(url, get_data)
        client = Client()
        request.session = client.session
        request.session["oidc_states"] = {
            "example_state": {"nonce": None, "added_on": time.time()},
            "example_state2": {"nonce": None, "added_on": time.time()},
        }
        callback_view = views.OIDCAuthenticationCallbackView.as_view()
        callback_view(request)

        self.assertFalse("example_state" in request.session["oidc_states"])
        self.assertTrue("example_state2" in request.session["oidc_states"])

    @override_settings(LOGIN_REDIRECT_URL="/success")
    def test_session_refresh_doesnt_call_login_again(self):
        """Test that a successful session refresh doesn't call django.contrib.auth.login
        again (which would cycle session keys and CSRF tokens)."""
        user = User.objects.create_user("example_username")

        def make_request():
            get_data = {"code": "example_code", "state": "example_state"}
            url = reverse("oidc_authentication_callback")
            request = self.factory.get(url, get_data)
            client = Client()
            request.session = client.session
            request.session["oidc_states"] = {
                "example_state": {"nonce": None, "added_on": time.time()},
            }
            return request

        request = make_request()
        callback_view = views.OIDCAuthenticationCallbackView.as_view()

        # Login the first time. This should call login()
        with patch("mozilla_django_oidc.views.auth.authenticate") as mock_auth:
            with patch("mozilla_django_oidc.views.auth.login") as mock_login:
                mock_auth.return_value = user
                response = callback_view(request)
                mock_auth.assert_called_once_with(
                    code_verifier=None, nonce=None, request=request
                )
                mock_login.assert_called_once_with(request, user)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/success")

        # Set the user on the request, to mimic a session refresh
        request = make_request()
        request.user = user

        # Login the second time. This should succeed, but not call login(), since the
        # user is already logged in.
        with patch("mozilla_django_oidc.views.auth.authenticate") as mock_auth:
            with patch("mozilla_django_oidc.views.auth.login") as mock_login:
                mock_auth.return_value = user
                response = callback_view(request)
                mock_auth.assert_called_once_with(
                    code_verifier=None, nonce=None, request=request
                )
                mock_login.assert_not_called()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/success")


class GetNextURLTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def build_request(self, next_url):
        return self.factory.get("/", data={"next": next_url})

    def test_no_param(self):
        req = self.factory.get("/")
        next_url = views.get_next_url(req, "next")
        self.assertIsNone(next_url)

    def test_non_next_param(self):
        req = self.factory.get("/", data={"redirectto": "/foo"})
        next_url = views.get_next_url(req, "redirectto")
        self.assertEqual(next_url, "/foo")

    def test_good_urls(self):
        urls = [
            "/",
            "/foo",
            "/foo?bar=baz",
            "http://testserver/foo",
        ]
        for url in urls:
            req = self.build_request(next_url=url)
            next_url = views.get_next_url(req, "next")

            self.assertEqual(next_url, url)

    def test_bad_urls(self):
        urls = [
            "",
            # NOTE(willkg): Test data taken from the Django url_has_allowed_host_and_scheme tests.
            "http://example.com",
            "http:///example.com",
            "https://example.com",
            "ftp://example.com",
            r"\\example.com",
            r"\\\example.com",
            r"/\\/example.com",
            r"\\\example.com",
            r"\\example.com",
            r"\\//example.com",
            r"/\/example.com",
            r"\/example.com",
            r"/\example.com",
            "http:///example.com",
            r"http:/\//example.com",
            r"http:\/example.com",
            r"http:/\example.com",
            'javascript:alert("XSS")',
            "\njavascript:alert(x)",
            "\x08//example.com",
            r"http://otherserver\@example.com",
            r"http:\\testserver\@example.com",
            r"http://testserver\me:pass@example.com",
            r"http://testserver\@example.com",
            r"http:\\testserver\confirm\me@example.com",
            "http:999999999",
            "ftp:9999999999",
            "\n",
        ]
        for url in urls:
            req = self.build_request(next_url=url)
            next_url = views.get_next_url(req, "next")

            self.assertIsNone(next_url)

    def test_https(self):
        # If the request is for HTTPS and the next url is HTTPS, then that
        # works with all Djangos.
        req = self.factory.get(
            "/",
            data={"next": "https://testserver/foo"},
            secure=True,
        )
        self.assertEqual(req.is_secure(), True)
        next_url = views.get_next_url(req, "next")
        self.assertEqual(next_url, "https://testserver/foo")

        # If the request is for HTTPS and the next url is HTTP, then that fails.
        req = self.factory.get(
            "/",
            data={"next": "http://testserver/foo"},
            secure=True,
        )
        self.assertEqual(req.is_secure(), True)
        next_url = views.get_next_url(req, "next")
        self.assertIsNone(next_url)

    @override_settings(OIDC_REDIRECT_REQUIRE_HTTPS=False)
    def test_redirect_https_not_required(self):
        req = self.factory.get("/", data={"next": "http://testserver/foo"}, secure=True)

        next_url = views.get_next_url(req, "next")
        self.assertEqual(next_url, "http://testserver/foo")

    @override_settings(OIDC_REDIRECT_ALLOWED_HOSTS=["example.com", "foo.com"])
    def test_redirect_allowed_hosts(self):
        req = self.factory.get(
            "/", data={"next": "https://example.com/foo"}, secure=True
        )

        next_url = views.get_next_url(req, "next")
        self.assertEqual(next_url, "https://example.com/foo")


class OIDCAuthorizationRequestViewTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT="https://server.example.com/auth")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    @override_settings(OIDC_USE_PKCE=True)
    @patch("mozilla_django_oidc.views.get_random_string")
    def test_get(self, mock_views_random):
        """Test initiation of a successful OIDC attempt."""
        mock_views_random.return_value = "examplestring"
        url = reverse("oidc_authentication_init")
        request = self.factory.get(url)
        request.session = dict()
        login_view = views.OIDCAuthenticationRequestView.as_view()
        response = login_view(request)
        self.assertEqual(response.status_code, 302)

        o = urlparse(response.url)
        query_dict = parse_qs(o.query)

        # The PKCE code_challenge should be a random string between 43 and 128 characters.
        # Since it's random, we can only test that it's present and has the right length.
        # Then we just insert it into the expected_query.
        self.assertIn("code_challenge", query_dict)
        self.assertTrue(
            len(query_dict["code_challenge"]) == 1
            and 43 <= len(query_dict["code_challenge"][0]) <= 128
        )
        expected_query = {
            "code_challenge": query_dict["code_challenge"],
            "code_challenge_method": ["S256"],
            "response_type": ["code"],
            "scope": ["openid email"],
            "client_id": ["example_id"],
            "redirect_uri": ["http://testserver/callback/"],
            "state": ["examplestring"],
            "nonce": ["examplestring"],
        }
        self.assertDictEqual(query_dict, expected_query)
        self.assertEqual(o.hostname, "server.example.com")
        self.assertEqual(o.path, "/auth")

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT="https://server.example.com/auth")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    @override_settings(OIDC_USE_PKCE=False)
    @patch("mozilla_django_oidc.views.get_random_string")
    def test_get_without_PKCE(self, mock_views_random):
        """Test initiation of a successful OIDC attempt with PKCE disabled."""
        mock_views_random.return_value = "examplestring"
        url = reverse("oidc_authentication_init")
        request = self.factory.get(url)
        request.session = dict()
        login_view = views.OIDCAuthenticationRequestView.as_view()
        response = login_view(request)
        self.assertEqual(response.status_code, 302)

        o = urlparse(response.url)
        query_dict = parse_qs(o.query)

        # PKCE is disabled, so code_challenge and code_challenge_method should not be present.
        expected_query = {
            "response_type": ["code"],
            "scope": ["openid email"],
            "client_id": ["example_id"],
            "redirect_uri": ["http://testserver/callback/"],
            "state": ["examplestring"],
            "nonce": ["examplestring"],
        }
        self.assertDictEqual(query_dict, expected_query)
        self.assertEqual(o.hostname, "server.example.com")
        self.assertEqual(o.path, "/auth")

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT="https://server.example.com/auth")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    @override_settings(OIDC_USE_PKCE=True)
    @override_settings(OIDC_PKCE_CODE_VERIFIER_SIZE=42)  # must be between 43 and 128
    @patch("mozilla_django_oidc.views.get_random_string")
    def test_get_invalid_code_verifier_size_too_short(self, mock_views_random):
        """Test initiation of an OIDC attempt with an invalid code verifier size."""
        mock_views_random.return_value = "examplestring"
        url = reverse("oidc_authentication_init")
        request = self.factory.get(url)
        request.session = dict()
        login_view = views.OIDCAuthenticationRequestView.as_view()
        try:
            login_view(request)
            self.fail(
                "OIDC_PKCE_CODE_VERIFIER_SIZE must be between 43 and 128,"
                " but OIDC_PKCE_CODE_VERIFIER_SIZE was 42 and no exception was raised."
            )
        except ValueError:
            pass

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT="https://server.example.com/auth")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    @override_settings(OIDC_USE_PKCE=True)
    @override_settings(OIDC_PKCE_CODE_VERIFIER_SIZE=129)  # must be between 43 and 128
    @patch("mozilla_django_oidc.views.get_random_string")
    def test_get_invalid_code_verifier_size_too_long(self, mock_views_random):
        """Test initiation of an OIDC attempt with an invalid code verifier size."""
        mock_views_random.return_value = "examplestring"
        url = reverse("oidc_authentication_init")
        request = self.factory.get(url)
        request.session = dict()
        login_view = views.OIDCAuthenticationRequestView.as_view()
        try:
            login_view(request)
            self.fail(
                "OIDC_PKCE_CODE_VERIFIER_SIZE must be between 43 and 128,"
                " but OIDC_PKCE_CODE_VERIFIER_SIZE was 129 and no exception was raised."
            )
        except ValueError:
            pass

    @override_settings(ROOT_URLCONF="tests.namespaced_urls")
    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT="https://server.example.com/auth")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    @override_settings(OIDC_USE_PKCE=True)
    @override_settings(
        OIDC_AUTHENTICATION_CALLBACK_URL="namespace:oidc_authentication_callback"
    )
    @patch("mozilla_django_oidc.views.get_random_string")
    def test_get_namespaced(self, mock_views_random):
        """Test initiation of a successful OIDC attempt with namespaced redirect_uri."""
        mock_views_random.return_value = "examplestring"
        url = reverse("namespace:oidc_authentication_init")
        request = self.factory.get(url)
        request.session = dict()
        login_view = views.OIDCAuthenticationRequestView.as_view()
        response = login_view(request)
        self.assertEqual(response.status_code, 302)

        o = urlparse(response.url)
        query_dict = parse_qs(o.query)

        # The PKCE code_challenge should be a random string between 43 and 128 characters.
        # Since it's random, we can only test that it's present and has the right length.
        # Then we just insert it into the expected_query.
        self.assertIn("code_challenge", query_dict)
        self.assertTrue(
            len(query_dict["code_challenge"]) == 1
            and 43 <= len(query_dict["code_challenge"][0]) <= 128
        )
        expected_query = {
            "code_challenge": query_dict["code_challenge"],
            "code_challenge_method": ["S256"],
            "response_type": ["code"],
            "scope": ["openid email"],
            "client_id": ["example_id"],
            "redirect_uri": ["http://testserver/namespace/callback/"],
            "state": ["examplestring"],
            "nonce": ["examplestring"],
        }
        self.assertDictEqual(query_dict, expected_query)
        self.assertEqual(o.hostname, "server.example.com")
        self.assertEqual(o.path, "/auth")

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT="https://server.example.com/auth")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    @override_settings(OIDC_USE_PKCE=True)
    @override_settings(
        OIDC_AUTH_REQUEST_EXTRA_PARAMS={"audience": "some-api.example.com"}
    )
    @patch("mozilla_django_oidc.views.get_random_string")
    def test_get_with_audience(self, mock_views_random):
        """Test initiation of a successful OIDC attempt."""
        mock_views_random.return_value = "examplestring"
        url = reverse("oidc_authentication_init")
        request = self.factory.get(url)
        request.session = dict()
        login_view = views.OIDCAuthenticationRequestView.as_view()
        response = login_view(request)
        self.assertEqual(response.status_code, 302)

        o = urlparse(response.url)
        query_dict = parse_qs(o.query)

        # The PKCE code_challenge should be a random string between 43 and 128 characters.
        # Since it's random, we can only test that it's present and has the right length.
        # Then we just insert it into the expected_query.
        self.assertIn("code_challenge", query_dict)
        self.assertTrue(
            len(query_dict["code_challenge"]) == 1
            and 43 <= len(query_dict["code_challenge"][0]) <= 128
        )
        expected_query = {
            "code_challenge": query_dict["code_challenge"],
            "code_challenge_method": ["S256"],
            "response_type": ["code"],
            "scope": ["openid email"],
            "client_id": ["example_id"],
            "redirect_uri": ["http://testserver/callback/"],
            "state": ["examplestring"],
            "nonce": ["examplestring"],
            "audience": ["some-api.example.com"],
        }
        self.assertDictEqual(query_dict, expected_query)
        self.assertEqual(o.hostname, "server.example.com")
        self.assertEqual(o.path, "/auth")

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT="https://server.example.com/auth")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    @override_settings(OIDC_USE_PKCE=True)
    @patch("mozilla_django_oidc.views.get_random_string")
    @patch("mozilla_django_oidc.views.OIDCAuthenticationRequestView.get_extra_params")
    def test_get_with_overridden_extra_params(
        self, mock_extra_params, mock_views_random
    ):
        """Test overriding OIDCAuthenticationRequestView.get_extra_params()."""
        mock_views_random.return_value = "examplestring"

        mock_extra_params.return_value = {"connection": "foo"}

        url = reverse("oidc_authentication_init")
        request = self.factory.get(url)
        request.session = dict()
        login_view = views.OIDCAuthenticationRequestView.as_view()
        response = login_view(request)
        self.assertEqual(response.status_code, 302)

        o = urlparse(response.url)
        query_dict = parse_qs(o.query)

        # The PKCE code_challenge should be a random string between 43 and 128 characters.
        # Since it's random, we can only test that it's present and has the right length.
        # Then we just insert it into the expected_query.
        self.assertIn("code_challenge", query_dict)
        self.assertTrue(
            len(query_dict["code_challenge"]) == 1
            and 43 <= len(query_dict["code_challenge"][0]) <= 128
        )
        expected_query = {
            "code_challenge": query_dict["code_challenge"],
            "code_challenge_method": ["S256"],
            "response_type": ["code"],
            "scope": ["openid email"],
            "client_id": ["example_id"],
            "redirect_uri": ["http://testserver/callback/"],
            "state": ["examplestring"],
            "nonce": ["examplestring"],
            "connection": ["foo"],
        }
        self.assertDictEqual(parse_qs(o.query), expected_query)
        self.assertEqual(o.hostname, "server.example.com")
        self.assertEqual(o.path, "/auth")

        mock_extra_params.assert_called_with(request)

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT="https://server.example.com/auth")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    def test_next_url(self):
        """Test that `next` url gets stored to user session."""
        url = reverse("oidc_authentication_init")
        request = self.factory.get("{url}?{params}".format(url=url, params="next=/foo"))
        request.session = dict()
        login_view = views.OIDCAuthenticationRequestView.as_view()
        login_view(request)
        self.assertTrue("oidc_login_next" in request.session)
        self.assertEqual(request.session["oidc_login_next"], "/foo")

    @override_settings(OIDC_OP_AUTHORIZATION_ENDPOINT="https://server.example.com/auth")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    def test_missing_next_url(self):
        """Test that `next` url gets invalidated in user session."""
        url = reverse("oidc_authentication_init")
        request = self.factory.get(url)
        request.session = {"oidc_login_next": "foobar"}
        login_view = views.OIDCAuthenticationRequestView.as_view()
        login_view(request)
        self.assertTrue("oidc_login_next" in request.session)
        self.assertTrue(request.session["oidc_login_next"] is None)


class OIDCLogoutViewTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(LOGOUT_REDIRECT_URL="/example-logout")
    def test_get_anonymous_user(self):
        url = reverse("oidc_logout")
        request = self.factory.post(url)
        request.user = AnonymousUser()
        logout_view = views.OIDCLogoutView.as_view()

        response = logout_view(request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/example-logout")

    @override_settings(LOGOUT_REDIRECT_URL="/example-logout")
    def test_post(self):
        user = User.objects.create_user("example_username")
        url = reverse("oidc_logout")
        request = self.factory.post(url)
        request.user = user
        logout_view = views.OIDCLogoutView.as_view()

        with patch("mozilla_django_oidc.views.auth.logout") as mock_logout:
            response = logout_view(request)
            mock_logout.assert_called_once_with(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/example-logout")

    @override_settings(LOGOUT_REDIRECT_URL="/example-logout")
    @override_settings(OIDC_OP_LOGOUT_URL_METHOD="tests.test_views.my_custom_op_logout")
    def test_post_with_OIDC_OP_LOGOUT_URL_METHOD(self):
        user = User.objects.create_user("example_username")
        url = reverse("oidc_logout")
        request = self.factory.post(url)
        request.user = user
        logout_view = views.OIDCLogoutView.as_view()

        with patch("mozilla_django_oidc.views.auth.logout") as mock_logout:
            response = logout_view(request)
            mock_logout.assert_called_once_with(request)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "http://testserver/logged/out")
