import requests
from mock import Mock, patch

from django.test import TestCase, override_settings

from mozilla_django_oidc.contrib.auth0.utils import refresh_id_token


class Auth0UtilsTestCase(TestCase):
    """Tests for the Auth0 utils."""

    @override_settings(OIDC_RP_CLIENT_ID='client_id')
    @override_settings(OIDC_OP_DOMAIN='op_domain')
    @patch('mozilla_django_oidc.contrib.auth0.utils.requests.post')
    def test_successful_refresh_token(self, mock_post):
        """Test a successful attempt for a refresh id_token."""
        mock_response = Mock()
        mock_response.json.return_value = {
            'id_token': 'foobar'
        }
        mock_post.return_value = mock_response
        self.assertEqual(refresh_id_token('token'), 'foobar')

    @override_settings(OIDC_RP_CLIENT_ID='client_id')
    @override_settings(OIDC_OP_DOMAIN='op_domain')
    @patch('mozilla_django_oidc.contrib.auth0.utils.requests.post')
    def test_unsuccessful_attempt(self, mock_post):
        """Test an attempt to get a refresh token that raises an error."""
        mock_response = Mock()
        http_error = requests.exceptions.HTTPError()
        mock_response.raise_for_status.side_effect = http_error
        mock_post.return_value = mock_response
        with self.assertRaises(Exception):
            self.assertEqual(refresh_id_token('token'), None)
