from unittest import TestCase

from django.test.client import Client

from mozilla_django_oidc.test import OIDCClient


class TestOIDCClient(TestCase):
    def test_inherits_from_django_test_client(self):
        self.assertIsInstance(OIDCClient(), Client)

    def test_oidc_id_token_is_set_to_some_token_by_default(self):
        self.assertEqual(OIDCClient.oidc_id_token, 'some_oidc_token')

    def test_sets_oidc_id_token_for_session(self):
        self.assertEqual(OIDCClient().session['oidc_id_token'], 'some_oidc_token')

    def test_sets_specified_id_token_for_session(self):
        class StubOIDCClient(OIDCClient):
            oidc_id_token = 'some_other_oidc_token'

        client = StubOIDCClient()
        self.assertEqual(client.session['oidc_id_token'], 'some_other_oidc_token')
