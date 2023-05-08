import unittest.mock

from django.core.exceptions import SuspiciousOperation
from django.test import RequestFactory, TestCase, override_settings
from rest_framework import exceptions

from mozilla_django_oidc.contrib.drf import OIDCAuthentication


class TestDRF(TestCase):
    @override_settings(OIDC_OP_TOKEN_ENDPOINT="https://server.example.com/token")
    @override_settings(OIDC_OP_USER_ENDPOINT="https://server.example.com/user")
    @override_settings(OIDC_RP_CLIENT_ID="example_id")
    @override_settings(OIDC_RP_CLIENT_SECRET="client_secret")
    def setUp(self):
        self.auth = OIDCAuthentication(backend=unittest.mock.Mock())
        self.request = RequestFactory().get("/", HTTP_AUTHORIZATION="Bearer faketoken")

    def test_authenticate_returns_none_if_no_access_token(self):
        with unittest.mock.patch.object(self.auth, "get_access_token", return_value=None):
            ret = self.auth.authenticate(self.request)
        self.assertIsNone(ret)

    def test_authenticate_raises_authenticationfailed_if_backend_returns_no_user(self):
        self.auth.backend.get_or_create_user.return_value = None
        with self.assertRaises(exceptions.AuthenticationFailed):
            self.auth.authenticate(self.request)

    def test_authenticate_raises_authenticationfailed_on_suspiciousoperation(self):
        self.auth.backend.get_or_create_user.side_effect = SuspiciousOperation
        with self.assertRaises(exceptions.AuthenticationFailed):
            self.auth.authenticate(self.request)

    def test_returns_user_and_token_if_backend_returns_user(self):
        user = unittest.mock.Mock()
        self.auth.backend.get_or_create_user.return_value = user
        ret = self.auth.authenticate(self.request)
        self.assertEqual(ret[0], user)
        self.assertEqual(ret[1], "faketoken")
