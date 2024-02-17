from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings
from django.test.client import RequestFactory
from unittest.mock import MagicMock

from mozilla_django_oidc.utils import (
    absolutify,
    add_state_and_verifier_and_nonce_to_session,
    base64_url_decode,
    base64_url_encode,
    generate_code_challenge,
    import_from_settings,
)


class SettingImportTestCase(TestCase):
    @override_settings(EXAMPLE_VARIABLE="example_value")
    def test_attr_existing_no_default_value(self):
        s = import_from_settings("EXAMPLE_VARIABLE")
        self.assertEqual(s, "example_value")

    def test_attr_nonexisting_no_default_value(self):
        with self.assertRaises(ImproperlyConfigured):
            import_from_settings("EXAMPLE_VARIABLE")

    def test_attr_nonexisting_default_value(self):
        s = import_from_settings("EXAMPLE_VARIABLE", "example_default")
        self.assertEqual(s, "example_default")


class AbsolutifyTestCase(TestCase):
    def test_absolutify(self):
        req = RequestFactory().get("/something/else")
        url = absolutify(req, "/foo/bar")
        self.assertEqual(url, "http://testserver/foo/bar")

        req = RequestFactory().get("/something/else", SERVER_PORT=8888)
        url = absolutify(req, "/foo/bar")
        self.assertEqual(url, "http://testserver:8888/foo/bar")

    @override_settings(SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"))
    def test_absolutify_https(self):
        req = RequestFactory(HTTP_X_FORWARDED_PROTO="https").get("/", SERVER_PORT=443)
        url = absolutify(req, "/foo/bar")
        self.assertEqual(url, "https://testserver/foo/bar")

    @override_settings(SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https"))
    def test_absolutify_path_host_injection(self):
        req = RequestFactory(HTTP_X_FORWARDED_PROTO="https").get("/", SERVER_PORT=443)
        url = absolutify(req, "evil.com/foo/bar")
        self.assertEqual(url, "https://testserver/evil.com/foo/bar")


class Base64URLEncodeTestCase(TestCase):
    def test_base64_url_encode(self):
        """
        Tests creating a url-safe base64 encoded string from bytes.
        Source: https://datatracker.ietf.org/doc/html/rfc7636#appendix-A
        """
        data = bytes((3, 236, 255, 224, 193))
        encoded = base64_url_encode(data)

        # Using base64.b64encode() returns b'A+z/4ME='.
        # Our implementation should strip tailing '='s padding.
        # and replace '+' with '-' and '/' with '_'.
        self.assertEqual(encoded, "A-z_4ME")

        # Decoding should return the original data.
        decoded = base64_url_decode(encoded)
        self.assertEqual(decoded, data)

    def test_base64_url_encode_empty_input(self):
        """
        Tests creating a url-safe base64 encoded string from an empty bytes instance.
        """
        data = bytes()
        encoded = base64_url_encode(data)
        self.assertEqual(encoded, "")

        decoded = base64_url_decode(encoded)
        self.assertEqual(decoded, data)

    def test_base64_url_encode_double_padding(self):
        """
        Test encoding a string whoose base64.b64encode encoding ends with '=='.
        """
        data = bytes((3, 236, 255, 224, 193, 222, 22))
        encoded = base64_url_encode(data)

        # Using base64.b64encode() returns b'A+z/4MHeFg=='.
        self.assertEqual(encoded, "A-z_4MHeFg")

        # Decoding should return the original data.
        decoded = base64_url_decode(encoded)
        self.assertEqual(decoded, data)


class PKCECodeVerificationTestCase(TestCase):
    def test_generate_code_challenge(self):
        """
        Tests that a code challenge is generated correctly with the 'S256' method.
        """
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        code_challenge = generate_code_challenge(code_verifier, "S256")

        self.assertEqual(code_challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")

    def test_generate_plain_code_challenge(self):
        """
        Tests that a code challenge is generated correctly with the 'plain' method.
        """
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        code_challenge = generate_code_challenge(code_verifier, "plain")

        self.assertEqual(code_challenge, code_verifier)

    def test_generate_code_challenge_invalid_method(self):
        """
        Tests that an exception is raised when an invalid code challenge method is provided.
        """
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        self.assertRaises(ValueError, generate_code_challenge, code_verifier, "INVALID")


class SessionStateTestCase(TestCase):
    def setUp(self):
        self.request = RequestFactory().get("/doesnt/matter")

        # Setup request with a session for testing
        middleware = SessionMiddleware(MagicMock())
        middleware.process_request(self.request)
        self.request.session.save()

    def test_add_state_to_session(self):
        state = "example_state"
        params = {}

        add_state_and_verifier_and_nonce_to_session(self.request, state, params)

        self.assertIn("oidc_states", self.request.session)
        self.assertEqual(1, len(self.request.session["oidc_states"]))
        self.assertIn(state, self.request.session["oidc_states"].keys())

    def test_multiple_states(self):
        state1 = "example_state_1"
        state2 = "example_state_2"
        params = {}

        add_state_and_verifier_and_nonce_to_session(self.request, state1, params)

        self.assertEqual(1, len(self.request.session["oidc_states"]))
        self.assertIn(state1, self.request.session["oidc_states"].keys())

        add_state_and_verifier_and_nonce_to_session(self.request, state2, params)

        self.assertEqual(2, len(self.request.session["oidc_states"]))
        self.assertIn(state1, self.request.session["oidc_states"].keys())
        self.assertIn(state2, self.request.session["oidc_states"].keys())

    def test_max_states(self):
        limit = import_from_settings("OIDC_MAX_STATES", 50)

        first_state = "example_state_0"
        params = {}
        for i in range(limit):
            state = "example_state_{}".format(i)
            add_state_and_verifier_and_nonce_to_session(self.request, state, params)

        self.assertEqual(limit, len(self.request.session["oidc_states"]))
        self.assertIn(first_state, self.request.session["oidc_states"])

        # Add another state which should remove the very first one
        additional_state = "example_state"
        add_state_and_verifier_and_nonce_to_session(
            self.request, additional_state, params
        )

        # Make sure the oldest state was deleted
        self.assertNotIn(first_state, self.request.session["oidc_states"])

        # New state should be in the list but length should not have changed
        self.assertEqual(limit, len(self.request.session["oidc_states"]))
        self.assertIn(additional_state, self.request.session["oidc_states"].keys())

    @override_settings(OIDC_USE_NONCE=False)
    def test_state_dictionary_without_nonce_format(self):
        state = "example_state"
        params = {}

        add_state_and_verifier_and_nonce_to_session(self.request, state, params)

        # Test state dictionary
        self.assertIn(state, self.request.session["oidc_states"].keys())
        self.assertTrue(isinstance(self.request.session["oidc_states"][state], dict))

        # Test nonce
        self.assertIsNone(self.request.session["oidc_states"][state]["nonce"])

        # Test added_on timestamp
        self.assertTrue(
            isinstance(self.request.session["oidc_states"][state]["added_on"], float)
        )

    def test_state_dictionary_with_nonce_format(self):
        state = "example_state"
        params = {"nonce": "example_nonce"}

        add_state_and_verifier_and_nonce_to_session(self.request, state, params)

        self.assertNotEqual(self.request.session["oidc_states"][state]["nonce"], None)
