import json
from unittest.mock import Mock, call, patch

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.test import RequestFactory, TestCase, override_settings
from django.utils.encoding import force_bytes, smart_str
from josepy.b64 import b64encode
from josepy.jwa import ES256

from mozilla_django_oidc.auth import OIDCAuthenticationBackend, default_username_algo

User = get_user_model()


class DefaultUsernameAlgoTestCase(TestCase):
    def run_test(self, data, expected):
        actual = default_username_algo(data)
        self.assertEqual(actual, expected)
        self.assertEqual(type(actual), type(expected))

    def test_empty(self):
        self.run_test("", "2jmj7l5rSw0yVb_vlWAYkK_YBwk")

    def test_email(self):
        self.run_test("janet@example.com", "VUCUpl08JVpFeAFKBYkAjLhsQ1c")


class OIDCAuthenticationBackendTestCase(TestCase):
    """Authentication tests."""

    @override_settings(OIDC_OP_TOKEN_ENDPOINT="https://server.example.com/token")
    @override_settings(OIDC_OP_USER_ENDPOINT="https://server.example.com/user")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    @override_settings(OIDC_RP_CLIENT_SECRET="client_secret")
    def setUp(self):
        self.backend = OIDCAuthenticationBackend()

    def test_missing_request_arg(self):
        """Test authentication returns `None` when `request` is not provided."""
        self.assertIsNone(self.backend.authenticate(request=None))

    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token")
    @patch("mozilla_django_oidc.auth.requests")
    def test_invalid_token(self, request_mock, token_mock):
        """Test authentication with an invalid token."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        token_mock.return_value = None
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "accesss_token": "access_token",
        }
        request_mock.post.return_value = post_json_mock
        self.assertIsNone(self.backend.authenticate(request=auth_request))

    @override_settings(OIDC_ALLOW_UNSECURED_JWT=True)
    def test_allowed_unsecured_token(self):
        """Test payload data from unsecured token (allowed)."""
        header = force_bytes(json.dumps({"alg": "none"}))
        payload = force_bytes(json.dumps({"foo": "bar"}))
        signature = ""
        token = force_bytes(
            "{}.{}.{}".format(
                smart_str(b64encode(header)), smart_str(b64encode(payload)), signature
            )
        )

        extracted_payload = self.backend.get_payload_data(token, None)
        self.assertEqual(payload, extracted_payload)

    @override_settings(OIDC_ALLOW_UNSECURED_JWT=False)
    def test_disallowed_unsecured_token(self):
        """Test payload data from unsecured token (disallowed)."""
        header = force_bytes(json.dumps({"alg": "none"}))
        payload = force_bytes(json.dumps({"foo": "bar"}))
        signature = ""
        token = force_bytes(
            "{}.{}.{}".format(
                smart_str(b64encode(header)), smart_str(b64encode(payload)), signature
            )
        )

        with self.assertRaises(KeyError):
            self.backend.get_payload_data(token, None)

    @override_settings(OIDC_ALLOW_UNSECURED_JWT=True)
    def test_allowed_unsecured_valid_token(self):
        """Test payload data from valid secured token (unsecured allowed)."""
        header = force_bytes(json.dumps({"alg": "HS256", "typ": "JWT"}))
        payload = force_bytes(json.dumps({"foo": "bar"}))

        # Compute signature
        key = b"mysupersecuretestkey"
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        msg = "{}.{}".format(
            smart_str(b64encode(header)), smart_str(b64encode(payload))
        )
        h.update(force_bytes(msg))
        signature = b64encode(h.finalize())

        token = "{}.{}.{}".format(
            smart_str(b64encode(header)),
            smart_str(b64encode(payload)),
            smart_str(signature),
        )
        token_bytes = force_bytes(token)
        key_text = smart_str(key)
        output = self.backend.get_payload_data(token_bytes, key_text)
        self.assertEqual(output, payload)

    @override_settings(OIDC_ALLOW_UNSECURED_JWT=False)
    def test_disallowed_unsecured_valid_token(self):
        """Test payload data from valid secure token (unsecured disallowed)."""
        header = force_bytes(json.dumps({"alg": "HS256", "typ": "JWT"}))
        payload = force_bytes(json.dumps({"foo": "bar"}))

        # Compute signature
        key = b"mysupersecuretestkey"
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        msg = "{}.{}".format(
            smart_str(b64encode(header)), smart_str(b64encode(payload))
        )
        h.update(force_bytes(msg))
        signature = b64encode(h.finalize())

        token = "{}.{}.{}".format(
            smart_str(b64encode(header)),
            smart_str(b64encode(payload)),
            smart_str(signature),
        )
        token_bytes = force_bytes(token)
        key_text = smart_str(key)
        output = self.backend.get_payload_data(token_bytes, key_text)
        self.assertEqual(output, payload)

    @override_settings(OIDC_ALLOW_UNSECURED_JWT=True)
    def test_allowed_unsecured_invalid_token(self):
        """Test payload data from invalid secure token (unsecured allowed)."""
        header = force_bytes(json.dumps({"alg": "HS256", "typ": "JWT"}))
        payload = force_bytes(json.dumps({"foo": "bar"}))

        # Compute signature
        key = b"mysupersecuretestkey"
        fake_key = b"mysupersecurefaketestkey"
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        msg = "{}.{}".format(
            smart_str(b64encode(header)), smart_str(b64encode(payload))
        )
        h.update(force_bytes(msg))
        signature = b64encode(h.finalize())

        token = "{}.{}.{}".format(
            smart_str(b64encode(header)),
            smart_str(b64encode(payload)),
            smart_str(signature),
        )
        token_bytes = force_bytes(token)
        key_text = smart_str(fake_key)

        with self.assertRaises(SuspiciousOperation) as ctx:
            self.backend.get_payload_data(token_bytes, key_text)
        self.assertEqual(ctx.exception.args[0], "JWS token verification failed.")

    @override_settings(OIDC_ALLOW_UNSECURED_JWT=False)
    def test_disallowed_unsecured_invalid_token(self):
        """Test payload data from invalid secure token (unsecured disallowed)."""
        header = force_bytes(json.dumps({"alg": "HS256", "typ": "JWT"}))
        payload = force_bytes(json.dumps({"foo": "bar"}))

        # Compute signature
        key = b"mysupersecuretestkey"
        fake_key = b"mysupersecurefaketestkey"
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        msg = "{}.{}".format(
            smart_str(b64encode(header)), smart_str(b64encode(payload))
        )
        h.update(force_bytes(msg))
        signature = b64encode(h.finalize())

        token = "{}.{}.{}".format(
            smart_str(b64encode(header)),
            smart_str(b64encode(payload)),
            smart_str(signature),
        )
        token_bytes = force_bytes(token)
        key_text = smart_str(fake_key)

        with self.assertRaises(SuspiciousOperation) as ctx:
            self.backend.get_payload_data(token_bytes, key_text)
        self.assertEqual(ctx.exception.args[0], "JWS token verification failed.")

    def test_get_user(self):
        """Test get_user method with valid user."""

        user = User.objects.create_user("example_username")
        self.assertEqual(self.backend.get_user(user.pk), user)

    def test_get_invalid_user(self):
        """Test get_user method with non existing user."""

        self.assertIsNone(self.backend.get_user(user_id=1))

    @override_settings(ROOT_URLCONF="tests.namespaced_urls")
    @override_settings(
        OIDC_AUTHENTICATION_CALLBACK_URL="namespace:oidc_authentication_callback"
    )
    @patch("mozilla_django_oidc.auth.requests")
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token")
    def test_successful_authentication_existing_user_namespaced(
        self, token_mock, request_mock
    ):
        """Test successful authentication for existing user."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        user = User.objects.create_user(
            username="a_username", email="email@example.com"
        )
        token_mock.return_value = True
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock

        post_data = {
            "client_id": "example_id",
            "client_secret": "client_secret",
            "grant_type": "authorization_code",
            "code": "foo",
            "redirect_uri": "http://testserver/namespace/callback/",
        }
        self.assertEqual(self.backend.authenticate(request=auth_request), user)
        token_mock.assert_called_once_with("id_token", nonce=None)
        request_mock.post.assert_called_once_with(
            "https://server.example.com/token",
            data=post_data,
            auth=None,
            verify=True,
            timeout=None,
            proxies=None,
        )
        request_mock.get.assert_called_once_with(
            "https://server.example.com/user",
            headers={"Authorization": "Bearer access_granted"},
            verify=True,
            timeout=None,
            proxies=None,
        )

    @patch("mozilla_django_oidc.auth.requests")
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token")
    def test_successful_authentication_existing_user(self, token_mock, request_mock):
        """Test successful authentication for existing user."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        user = User.objects.create_user(
            username="a_username", email="email@example.com"
        )
        token_mock.return_value = True
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock

        post_data = {
            "client_id": "example_id",
            "client_secret": "client_secret",
            "grant_type": "authorization_code",
            "code": "foo",
            "redirect_uri": "http://testserver/callback/",
        }
        self.assertEqual(self.backend.authenticate(request=auth_request), user)
        token_mock.assert_called_once_with("id_token", nonce=None)
        request_mock.post.assert_called_once_with(
            "https://server.example.com/token",
            data=post_data,
            auth=None,
            verify=True,
            timeout=None,
            proxies=None,
        )
        request_mock.get.assert_called_once_with(
            "https://server.example.com/user",
            headers={"Authorization": "Bearer access_granted"},
            verify=True,
            timeout=None,
            proxies=None,
        )

    @override_settings(OIDC_STORE_ACCESS_TOKEN=True)
    @override_settings(OIDC_STORE_ID_TOKEN=True)
    @patch("mozilla_django_oidc.auth.requests")
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token")
    def test_successful_authentication_existing_user_upper_case(
        self, token_mock, request_mock
    ):
        """Test successful authentication for existing user regardless of email case."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        user = User.objects.create_user(
            username="a_username", email="EMAIL@EXAMPLE.COM"
        )
        token_mock.return_value = True
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock

        post_data = {
            "client_id": "example_id",
            "client_secret": "client_secret",
            "grant_type": "authorization_code",
            "code": "foo",
            "redirect_uri": "http://testserver/callback/",
        }
        self.assertEqual(self.backend.authenticate(request=auth_request), user)
        token_mock.assert_called_once_with("id_token", nonce=None)
        request_mock.post.assert_called_once_with(
            "https://server.example.com/token",
            data=post_data,
            auth=None,
            verify=True,
            timeout=None,
            proxies=None,
        )
        request_mock.get.assert_called_once_with(
            "https://server.example.com/user",
            headers={"Authorization": "Bearer access_granted"},
            verify=True,
            timeout=None,
            proxies=None,
        )
        self.assertEqual(auth_request.session.get("oidc_id_token"), "id_token")
        self.assertEqual(
            auth_request.session.get("oidc_access_token"), "access_granted"
        )

    @patch("mozilla_django_oidc.auth.requests")
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token")
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_claims")
    def test_failed_authentication_verify_claims(
        self, claims_mock, token_mock, request_mock
    ):
        """Test successful authentication for existing user."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        User.objects.create_user(username="a_username", email="email@example.com")
        token_mock.return_value = True
        claims_mock.return_value = False
        get_json_mock = Mock()
        claims_response = {"nickname": "a_username", "email": "email@example.com"}
        get_json_mock.json.return_value = claims_response
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock

        post_data = {
            "client_id": "example_id",
            "client_secret": "client_secret",
            "grant_type": "authorization_code",
            "code": "foo",
            "redirect_uri": "http://testserver/callback/",
        }
        self.assertIsNone(self.backend.authenticate(request=auth_request))
        token_mock.assert_called_once_with("id_token", nonce=None)
        claims_mock.assert_called_once_with(claims_response)
        request_mock.post.assert_called_once_with(
            "https://server.example.com/token",
            data=post_data,
            auth=None,
            verify=True,
            timeout=None,
            proxies=None,
        )
        request_mock.get.assert_called_once_with(
            "https://server.example.com/user",
            headers={"Authorization": "Bearer access_granted"},
            verify=True,
            timeout=None,
            proxies=None,
        )

    @patch.object(settings, "OIDC_USERNAME_ALGO")
    @patch("mozilla_django_oidc.auth.requests")
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token")
    def test_successful_authentication_new_user(
        self, token_mock, request_mock, algo_mock
    ):
        """Test successful authentication and user creation."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        algo_mock.return_value = "username_algo"
        token_mock.return_value = True
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock
        post_data = {
            "client_id": "example_id",
            "client_secret": "client_secret",
            "grant_type": "authorization_code",
            "code": "foo",
            "redirect_uri": "http://testserver/callback/",
        }
        self.assertEqual(User.objects.all().count(), 0)
        self.backend.authenticate(request=auth_request)
        self.assertEqual(User.objects.all().count(), 1)
        user = User.objects.all()[0]
        self.assertEqual(user.email, "email@example.com")
        self.assertEqual(user.username, "username_algo")

        token_mock.assert_called_once_with("id_token", nonce=None)
        request_mock.post.assert_called_once_with(
            "https://server.example.com/token",
            data=post_data,
            auth=None,
            verify=True,
            timeout=None,
            proxies=None,
        )
        request_mock.get.assert_called_once_with(
            "https://server.example.com/user",
            headers={"Authorization": "Bearer access_granted"},
            verify=True,
            timeout=None,
            proxies=None,
        )

    @override_settings(OIDC_TOKEN_USE_BASIC_AUTH=True)
    @override_settings(OIDC_STORE_ACCESS_TOKEN=True)
    @override_settings(OIDC_STORE_ID_TOKEN=True)
    @patch("mozilla_django_oidc.auth.requests")
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.verify_token")
    def test_successful_authentication_basic_auth_token(self, token_mock, request_mock):
        """
        Test successful authentication when using HTTP basic authentication
        for token endpoint authentication.
        """
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        user = User.objects.create_user(
            username="a_username", email="EMAIL@EXAMPLE.COM"
        )
        token_mock.return_value = True
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock

        post_data = {
            "client_id": "example_id",
            "client_secret": "client_secret",
            "grant_type": "authorization_code",
            "code": "foo",
            "redirect_uri": "http://testserver/callback/",
        }
        self.assertEqual(self.backend.authenticate(request=auth_request), user)
        token_mock.assert_called_once_with("id_token", nonce=None)

        # As the auth parameter is and object, we can't compare them directly
        request_mock.post.assert_called_once()
        post_params = request_mock.post.call_args
        _kwargs = post_params[1]

        self.assertEqual(post_params[0][0], "https://server.example.com/token")
        # Test individual params separately
        sent_data = _kwargs["data"]
        self.assertEqual(sent_data["client_id"], post_data["client_id"])
        self.assertTrue("client_secret" not in _kwargs["data"])
        self.assertEqual(sent_data["grant_type"], post_data["grant_type"])
        self.assertEqual(sent_data["code"], post_data["code"])
        self.assertEqual(sent_data["redirect_uri"], post_data["redirect_uri"])

        auth = _kwargs["auth"]  # requests.auth.HTTPBasicAuth
        self.assertEqual(auth.username, "example_id")
        self.assertEqual(auth.password, "client_secret")
        self.assertEqual(_kwargs["verify"], True)

        request_mock.get.assert_called_once_with(
            "https://server.example.com/user",
            headers={"Authorization": "Bearer access_granted"},
            verify=True,
            timeout=None,
            proxies=None,
        )
        self.assertEqual(auth_request.session.get("oidc_id_token"), "id_token")
        self.assertEqual(
            auth_request.session.get("oidc_access_token"), "access_granted"
        )

    def test_authenticate_no_code_no_state(self):
        """Test authenticate with wrong parameters."""

        # there are no GET params
        request = RequestFactory().get("/foo")
        request.session = {}
        self.assertIsNone(self.backend.authenticate(request=request))

    @override_settings(OIDC_USE_NONCE=False)
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.requests")
    def test_jwt_decode_params(self, request_mock, jws_mock):
        """Test jwt verification signature."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        jws_mock.return_value = json.dumps({"aud": "audience"}).encode("utf-8")
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "token",
            "access_token": "access_token",
        }
        request_mock.post.return_value = post_json_mock
        self.backend.authenticate(request=auth_request)
        calls = [call(force_bytes("token"), "client_secret")]
        jws_mock.assert_has_calls(calls)

    @override_settings(OIDC_VERIFY_JWT=False)
    @override_settings(OIDC_USE_NONCE=False)
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.requests")
    def test_jwt_decode_params_verify_false(self, request_mock, jws_mock):
        """Test jwt verification signature with verify False"""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        jws_mock.return_value = json.dumps({"aud": "audience"}).encode("utf-8")
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "token",
            "access_token": "access_token",
        }
        request_mock.post.return_value = post_json_mock
        calls = [call(force_bytes("token"), "client_secret")]
        self.backend.authenticate(request=auth_request)
        jws_mock.assert_has_calls(calls)

    @override_settings(OIDC_USE_NONCE=True)
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    def test_jwt_failed_nonce(self, jws_mock):
        """Test Nonce verification."""

        jws_mock.return_value = json.dumps({"nonce": "foobar", "aud": "aud"}).encode(
            "utf-8"
        )
        id_token = "my_token"
        with self.assertRaisesMessage(
            SuspiciousOperation, "JWT Nonce verification failed."
        ):
            self.backend.verify_token(id_token, **{"nonce": "foo"})

    @override_settings(OIDC_CREATE_USER=False)
    @override_settings(OIDC_USE_NONCE=False)
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.requests")
    def test_create_user_disabled(self, request_mock, jws_mock):
        """Test with user creation disabled and no user found."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        jws_mock.return_value = json.dumps({"nonce": "nonce"}).encode("utf-8")
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock
        self.assertIsNone(self.backend.authenticate(request=auth_request))

    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.requests")
    @override_settings(OIDC_USE_NONCE=False)
    def test_create_user_enabled(self, request_mock, jws_mock):
        """Test with user creation enabled and no user found."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        self.assertEqual(User.objects.filter(email="email@example.com").exists(), False)
        jws_mock.return_value = json.dumps({"nonce": "nonce"}).encode("utf-8")
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock
        self.assertEqual(
            self.backend.authenticate(request=auth_request),
            User.objects.get(email="email@example.com"),
        )

    @patch.object(settings, "OIDC_USERNAME_ALGO")
    @override_settings(OIDC_USE_NONCE=False)
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.requests")
    def test_custom_username_algo(self, request_mock, jws_mock, algo_mock):
        """Test user creation with custom username algorithm."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        self.assertEqual(User.objects.filter(email="email@example.com").exists(), False)
        algo_mock.return_value = "username_algo"
        jws_mock.return_value = json.dumps({"nonce": "nonce"}).encode("utf-8")
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock
        self.assertEqual(
            self.backend.authenticate(request=auth_request),
            User.objects.get(username="username_algo"),
        )

    @override_settings(
        OIDC_USE_NONCE=False,
        OIDC_USERNAME_ALGO="tests.test_auth.dotted_username_algo_callback",
    )
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.requests")
    def test_custom_username_algo_dotted_path(self, request_mock, jws_mock):
        """Test user creation with custom username algorithm with a dotted path."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        self.assertEqual(User.objects.filter(email="email@example.com").exists(), False)
        jws_mock.return_value = json.dumps({"nonce": "nonce"}).encode("utf-8")
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock
        self.assertEqual(
            self.backend.authenticate(request=auth_request),
            User.objects.get(username="dotted_username_algo"),
        )

    @override_settings(
        OIDC_USE_NONCE=False,
        OIDC_USERNAME_ALGO="tests.test_auth.dotted_username_algo_callback_with_claims",
    )
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.requests")
    def test_dotted_username_algo_callback_with_claims(self, request_mock, jws_mock):
        """Test user creation with custom username algorithm with a dotted path."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        self.assertEqual(User.objects.filter(email="email@example.com").exists(), False)
        jws_mock.return_value = json.dumps({"nonce": "nonce"}).encode("utf-8")
        domain = "django.con"
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
            "domain": domain,
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock
        self.assertEqual(
            self.backend.authenticate(request=auth_request),
            User.objects.get(username=f"{domain}/email@example.com"),
        )

    @override_settings(OIDC_USE_NONCE=False)
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.requests")
    def test_duplicate_emails_exact(self, request_mock, jws_mock):
        """Test auth with two users having the same email."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        User.objects.create(username="user1", email="email@example.com")
        User.objects.create(username="user2", email="email@example.com")
        jws_mock.return_value = json.dumps({"nonce": "nonce"}).encode("utf-8")
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock
        self.assertIsNone(self.backend.authenticate(request=auth_request))

    @override_settings(OIDC_USE_NONCE=False)
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.requests")
    def test_duplicate_emails_case_mismatch(self, request_mock, jws_mock):
        """Test auth with two users having the same email, with different case."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        User.objects.create(username="user1", email="email@example.com")
        User.objects.create(username="user2", email="eMaIl@ExAmPlE.cOm")
        jws_mock.return_value = json.dumps({"nonce": "nonce"}).encode("utf-8")
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock
        self.assertIsNone(self.backend.authenticate(request=auth_request))

    @override_settings(OIDC_USE_NONCE=False)
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.update_user")
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.requests")
    def test_custom_update_user(self, request_mock, jws_mock, update_user_mock):
        """User updated with new claims"""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        User.objects.create(
            username="user1", email="email@example.com", first_name="User"
        )

        def update_user(user, claims):
            user.first_name = claims["nickname"]
            user.save()

        update_user_mock.side_effect = update_user

        jws_mock.return_value = json.dumps({"nonce": "nonce"}).encode("utf-8")
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "a_username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "id_token",
            "access_token": "access_granted",
        }
        request_mock.post.return_value = post_json_mock
        self.assertIsNone(self.backend.authenticate(request=auth_request))

        self.assertEqual(User.objects.get().first_name, "a_username")


class OIDCAuthenticationBackendRS256WithKeyTestCase(TestCase):
    """Authentication tests with ALG RS256 and provided IdP Sign Key."""

    @override_settings(OIDC_OP_TOKEN_ENDPOINT="https://server.example.com/token")
    @override_settings(OIDC_OP_USER_ENDPOINT="https://server.example.com/user")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    @override_settings(OIDC_RP_CLIENT_SECRET="client_secret")
    @override_settings(OIDC_RP_SIGN_ALGO="RS256")
    @override_settings(OIDC_RP_IDP_SIGN_KEY="sign_key")
    def setUp(self):
        self.backend = OIDCAuthenticationBackend()

    @override_settings(OIDC_USE_NONCE=False)
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.requests")
    def test_jwt_verify_sign_key(self, request_mock, jws_mock):
        """Test jwt verification signature."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        jws_mock.return_value = json.dumps({"aud": "audience"}).encode("utf-8")
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "token",
            "access_token": "access_token",
        }
        request_mock.post.return_value = post_json_mock
        self.backend.authenticate(request=auth_request)
        calls = [call(force_bytes("token"), "sign_key")]
        jws_mock.assert_has_calls(calls)


class OIDCAuthenticationBackendRS256WithJwksEndpointTestCase(TestCase):
    """Authentication tests with ALG RS256 and IpD JWKS Endpoint."""

    @override_settings(OIDC_OP_TOKEN_ENDPOINT="https://server.example.com/token")
    @override_settings(OIDC_OP_USER_ENDPOINT="https://server.example.com/user")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    @override_settings(OIDC_RP_CLIENT_SECRET="client_secret")
    @override_settings(OIDC_RP_SIGN_ALGO="RS256")
    @override_settings(OIDC_OP_JWKS_ENDPOINT="https://server.example.com/jwks")
    def setUp(self):
        self.backend = OIDCAuthenticationBackend()

    @override_settings(OIDC_USE_NONCE=False)
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend._verify_jws")
    @patch("mozilla_django_oidc.auth.OIDCAuthenticationBackend.retrieve_matching_jwk")
    @patch("mozilla_django_oidc.auth.requests")
    def test_jwt_verify_sign_key_calls(self, request_mock, jwk_mock, jws_mock):
        """Test jwt verification signature."""
        auth_request = RequestFactory().get("/foo", {"code": "foo", "state": "bar"})
        auth_request.session = {}

        jwk_mock_ret = {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "cc7d29c9cb3780741cc0876633c9107a0f33c289",
            "n": "20LvblCBaPicNV3-NnJuahqbpi-b8hFD",
            "e": "AQAB",
        }
        jwk_mock.return_value = jwk_mock_ret

        jws_mock.return_value = json.dumps({"aud": "audience"}).encode("utf-8")
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "nickname": "username",
            "email": "email@example.com",
        }
        request_mock.get.return_value = get_json_mock
        post_json_mock = Mock(status_code=200)
        post_json_mock.json.return_value = {
            "id_token": "token",
            "access_token": "access_token",
        }
        request_mock.post.return_value = post_json_mock
        self.backend.authenticate(request=auth_request)
        calls = [call(force_bytes("token"), jwk_mock_ret)]
        jws_mock.assert_has_calls(calls)

    @patch("mozilla_django_oidc.auth.requests")
    def test_retrieve_matching_jwk(self, mock_requests):
        """Test retrieving valid jwk"""

        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "keys": [
                {
                    "alg": "RS256",
                    "kid": "foobar",
                },
                {
                    "alg": "RS512",
                    "kid": "foobar512",
                },
            ]
        }
        mock_requests.get.return_value = get_json_mock

        header = force_bytes(
            json.dumps({"alg": "RS256", "typ": "JWT", "kid": "foobar"})
        )
        payload = force_bytes(json.dumps({"foo": "bar"}))

        # Compute signature
        key = b"mysupersecuretestkey"
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        msg = "{}.{}".format(
            smart_str(b64encode(header)), smart_str(b64encode(payload))
        )
        h.update(force_bytes(msg))
        signature = b64encode(h.finalize())

        token = "{}.{}.{}".format(
            smart_str(b64encode(header)),
            smart_str(b64encode(payload)),
            smart_str(signature),
        )

        jwk_key = self.backend.retrieve_matching_jwk(force_bytes(token))
        self.assertEqual(jwk_key, get_json_mock.json.return_value["keys"][0])

    @patch("mozilla_django_oidc.auth.requests")
    def test_retrieve_matching_jwk_same_kid(self, mock_requests):
        """Test retrieving valid jwk from a list of keys with the same kid"""

        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "keys": [
                {
                    "alg": "RS512",
                    "kid": "foobar",
                },
                {
                    "alg": "RS384",
                    "kid": "foobar",
                },
                {
                    "alg": "RS256",
                    "kid": "foobar",
                },
            ]
        }
        mock_requests.get.return_value = get_json_mock

        header = force_bytes(
            json.dumps({"alg": "RS256", "typ": "JWT", "kid": "foobar"})
        )
        payload = force_bytes(json.dumps({"foo": "bar"}))

        # Compute signature
        key = b"mysupersecuretestkey"
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        msg = "{}.{}".format(
            smart_str(b64encode(header)), smart_str(b64encode(payload))
        )
        h.update(force_bytes(msg))
        signature = b64encode(h.finalize())

        token = "{}.{}.{}".format(
            smart_str(b64encode(header)),
            smart_str(b64encode(payload)),
            smart_str(signature),
        )

        jwk_key = self.backend.retrieve_matching_jwk(force_bytes(token))
        self.assertEqual(jwk_key, get_json_mock.json.return_value["keys"][2])

    @patch("mozilla_django_oidc.auth.requests")
    def test_retrieve_mismatcing_jwk_alg(self, mock_requests):
        """Test retrieving mismatching jwk alg"""

        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "keys": [
                {
                    "alg": "foo",
                    "kid": "bar",
                }
            ]
        }
        mock_requests.get.return_value = get_json_mock

        header = force_bytes(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "bar"}))
        payload = force_bytes(json.dumps({"foo": "bar"}))

        # Compute signature
        key = b"mysupersecuretestkey"
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        msg = "{}.{}".format(
            smart_str(b64encode(header)), smart_str(b64encode(payload))
        )
        h.update(force_bytes(msg))
        signature = b64encode(h.finalize())

        token = "{}.{}.{}".format(
            smart_str(b64encode(header)),
            smart_str(b64encode(payload)),
            smart_str(signature),
        )

        with self.assertRaises(SuspiciousOperation) as ctx:
            self.backend.retrieve_matching_jwk(force_bytes(token))

        self.assertEqual(ctx.exception.args[0], "Could not find a valid JWKS.")

    @patch("mozilla_django_oidc.auth.requests")
    def test_retrieve_mismatcing_jwk_kid(self, mock_requests):
        """Test retrieving mismatching jwk kid"""

        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "keys": [
                {
                    "alg": "HS256",
                    "kid": "foobar",
                }
            ]
        }
        mock_requests.get.return_value = get_json_mock

        header = force_bytes(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "bar"}))
        payload = force_bytes(json.dumps({"foo": "bar"}))

        # Compute signature
        key = b"mysupersecuretestkey"
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        msg = "{}.{}".format(
            smart_str(b64encode(header)), smart_str(b64encode(payload))
        )
        h.update(force_bytes(msg))
        signature = b64encode(h.finalize())

        token = "{}.{}.{}".format(
            smart_str(b64encode(header)),
            smart_str(b64encode(payload)),
            smart_str(signature),
        )

        with self.assertRaises(SuspiciousOperation) as ctx:
            self.backend.retrieve_matching_jwk(force_bytes(token))

        self.assertEqual(ctx.exception.args[0], "Could not find a valid JWKS.")

    @patch("mozilla_django_oidc.auth.requests")
    def test_retrieve_jwk_optional_alg(self, mock_requests):
        """Test retrieving jwk with optional alg"""

        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "keys": [
                {
                    "kid": "kid",
                }
            ]
        }
        mock_requests.get.return_value = get_json_mock

        header = force_bytes(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "kid"}))
        payload = force_bytes(json.dumps({"foo": "bar"}))

        # Compute signature
        key = b"mysupersecuretestkey"
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        msg = "{}.{}".format(
            smart_str(b64encode(header)), smart_str(b64encode(payload))
        )
        h.update(force_bytes(msg))
        signature = b64encode(h.finalize())

        token = "{}.{}.{}".format(
            smart_str(b64encode(header)),
            smart_str(b64encode(payload)),
            smart_str(signature),
        )

        jwk_key = self.backend.retrieve_matching_jwk(force_bytes(token))
        self.assertEqual(jwk_key, get_json_mock.json.return_value["keys"][0])

    @patch("mozilla_django_oidc.auth.requests")
    def test_retrieve_not_existing_jwk(self, mock_requests):
        """Test retrieving jwk that doesn't exist."""

        get_json_mock = Mock()
        get_json_mock.json.return_value = {"keys": [{"alg": "RS256", "kid": "kid"}]}
        mock_requests.get.return_value = get_json_mock

        header = force_bytes(
            json.dumps({"alg": "RS256", "typ": "JWT", "kid": "differentkid"})
        )
        payload = force_bytes(json.dumps({"foo": "bar"}))

        # Compute signature
        key = b"mysupersecuretestkey"
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        msg = "{}.{}".format(
            smart_str(b64encode(header)), smart_str(b64encode(payload))
        )
        h.update(force_bytes(msg))
        signature = b64encode(h.finalize())

        token = "{}.{}.{}".format(
            smart_str(b64encode(header)),
            smart_str(b64encode(payload)),
            smart_str(signature),
        )

        with self.assertRaises(SuspiciousOperation) as ctx:
            self.backend.retrieve_matching_jwk(force_bytes(token))

        self.assertEqual(ctx.exception.args[0], "Could not find a valid JWKS.")


class TestVerifyClaim(TestCase):
    @patch("mozilla_django_oidc.auth.import_from_settings")
    def test_returns_false_if_email_not_in_claims(self, patch_settings):
        patch_settings.return_value = "openid email"
        ret = OIDCAuthenticationBackend().verify_claims({})
        self.assertFalse(ret)

    @patch("mozilla_django_oidc.auth.import_from_settings")
    def test_returns_true_if_email_in_claims(self, patch_settings):
        patch_settings.return_value = "openid email"
        ret = OIDCAuthenticationBackend().verify_claims({"email": "email@example.com"})
        self.assertTrue(ret)

    @patch("mozilla_django_oidc.auth.import_from_settings")
    @patch("mozilla_django_oidc.auth.LOGGER")
    def test_returns_true_custom_claims(self, patch_logger, patch_settings):
        patch_settings.return_value = "foo bar"
        ret = OIDCAuthenticationBackend().verify_claims({})
        self.assertTrue(ret)
        msg = (
            "Custom OIDC_RP_SCOPES defined. "
            "You need to override `verify_claims` for custom claims verification."
        )
        patch_logger.warning.assert_called_with(msg)


def dotted_username_algo_callback(email):
    return "dotted_username_algo"


def dotted_username_algo_callback_with_claims(email, claims=None):
    domain = claims["domain"]
    username = f"{domain}/{email}"
    return username


@override_settings(OIDC_OP_TOKEN_ENDPOINT="https://server.example.com/token")
@override_settings(OIDC_OP_USER_ENDPOINT="https://server.example.com/user")
@override_settings(OIDC_RP_CLIENT_ID="example_id")
@override_settings(OIDC_RP_CLIENT_SECRET="client_secret")
@override_settings(OIDC_RP_SIGN_ALGO="ES256")
class OIDCAuthenticationBackendES256WithJwksEndpointTestCase(TestCase):
    """Authentication tests with ALG ES256 and IpD JWKS Endpoint."""

    def test_es256_alg_misconfiguration(self):
        """Test that ES algorithm requires a JWKS endpoint"""

        with self.assertRaises(ImproperlyConfigured) as ctx:
            OIDCAuthenticationBackend()

        self.assertEqual(
            ctx.exception.args[0],
            "ES256 alg requires OIDC_RP_IDP_SIGN_KEY or OIDC_OP_JWKS_ENDPOINT to be configured.",
        )

    @patch("mozilla_django_oidc.auth.requests")
    @override_settings(OIDC_OP_JWKS_ENDPOINT="https://server.example.com/jwks")
    def test_es256_alg_verification(self, mock_requests):
        """Test that token can be verified with the ES algorithm"""

        self.backend = OIDCAuthenticationBackend()

        # Generate a private key to create a test token with
        private_key = ec.generate_private_key(ec.SECP256R1, default_backend())
        private_key_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

        # Make the public key available through the JWKS response
        public_numbers = private_key.public_key().public_numbers()
        get_json_mock = Mock()
        get_json_mock.json.return_value = {
            "keys": [
                {
                    "kid": "eckid",
                    "kty": "EC",
                    "alg": "ES256",
                    "use": "sig",
                    "x": smart_str(b64encode(public_numbers.x.to_bytes(32, "big"))),
                    "y": smart_str(b64encode(public_numbers.y.to_bytes(32, "big"))),
                    "crv": "P-256",
                }
            ]
        }
        mock_requests.get.return_value = get_json_mock

        header = force_bytes(
            json.dumps(
                {
                    "typ": "JWT",
                    "alg": "ES256",
                    "kid": "eckid",
                },
            )
        )
        data = {"name": "John Doe", "test": "test_es256_alg_verification"}

        h = hmac.HMAC(private_key_pem, hashes.SHA256(), backend=default_backend())
        msg = "{}.{}".format(
            smart_str(b64encode(header)),
            smart_str(b64encode(force_bytes(json.dumps(data)))),
        )
        h.update(force_bytes(msg))

        signature = b64encode(ES256.sign(private_key, force_bytes(msg)))
        token = "{}.{}".format(
            msg,
            smart_str(signature),
        )

        # Verify the token created with the private key by using the JWKS endpoint,
        # where the public numbers are.
        payload = self.backend.verify_token(token)

        self.assertEqual(payload, data)
        mock_requests.get.assert_called_once()
