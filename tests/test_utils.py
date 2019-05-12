from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings
from django.test.client import RequestFactory
from mock import patch, Mock

from mozilla_django_oidc.constants import OIDCCacheKey
from mozilla_django_oidc.utils import absolutify, import_from_settings, \
    get_op_metadata, _op_metadata_settings, \
    extract_settings_from_op_metadata, get_from_op_metadata


class SettingImportTestCase(TestCase):

    @override_settings(EXAMPLE_VARIABLE='example_value')
    def test_attr_existing_no_default_value(self):
        s = import_from_settings('EXAMPLE_VARIABLE')
        self.assertEqual(s, 'example_value')

    def test_attr_nonexisting_no_default_value(self):
        with self.assertRaises(ImproperlyConfigured):
            import_from_settings('EXAMPLE_VARIABLE')

    def test_attr_nonexisting_default_value(self):
        s = import_from_settings('EXAMPLE_VARIABLE', 'example_default')
        self.assertEqual(s, 'example_default')


class AbsolutifyTestCase(TestCase):

    def test_absolutify(self):
        req = RequestFactory().get('/something/else')
        url = absolutify(req, '/foo/bar')
        self.assertEqual(url, 'http://testserver/foo/bar')

        req = RequestFactory().get('/something/else', SERVER_PORT=8888)
        url = absolutify(req, '/foo/bar')
        self.assertEqual(url, 'http://testserver:8888/foo/bar')

    @override_settings(SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'))
    def test_absolutify_https(self):
        req = RequestFactory(
            HTTP_X_FORWARDED_PROTO='https'
        ).get('/', SERVER_PORT=443)
        url = absolutify(req, '/foo/bar')
        self.assertEqual(url, 'https://testserver/foo/bar')

    @override_settings(SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'))
    def test_absolutify_path_host_injection(self):
        req = RequestFactory(
            HTTP_X_FORWARDED_PROTO='https'
        ).get('/', SERVER_PORT=443)
        url = absolutify(req, 'evil.com/foo/bar')
        self.assertEqual(url, 'https://testserver/evil.com/foo/bar')


class GetOPMetadataTestCase(TestCase):

    @override_settings(OIDC_VERIFY_SSL=True)
    @patch('mozilla_django_oidc.utils.requests')
    def test_get_op_metadata(self, requests_patch):
        """Testing that get_op_metadata is getting an url and giving a json"""
        test_json_mock = Mock()
        test_json_mock.json.return_value = {'test_key': 'test_value'}
        requests_patch.get.return_value = test_json_mock

        self.assertEqual(get_op_metadata('test_endpoint'), {'test_key': 'test_value'})
        requests_patch.get.assert_called_once_with(url='test_endpoint', verify=True)


class ExtractSettingsFromOPMetadataTestCase(TestCase):

    def test_extract_settings_from_op_metadata(self):
        """
        Testing that all the metadata settings configured in utils should result non none values
        after metadata extraction.
        """
        op_metadata_sample_dict = {
            'authorization_endpoint': 'test_auth',
            'token_endpoint': 'test_token',
            'userinfo_endpoint': 'test_userinfo',
            'jwks_uri': 'test_jwks'
        }
        for attr in _op_metadata_settings:
            self.assertIsNotNone(extract_settings_from_op_metadata(op_metadata_sample_dict, attr))

    def test_extract_settings_from_op_metadata_faulty_metadata(self):
        """Testing 'KeyError' is raised when metadata is faulty"""
        op_metadata_faulty_dict = {
            'token_endpoint': 'test_token',
            'userinfo_endpoint': 'test_userinfo',
            'jwks_uri': 'test_jwks'
        }
        with self.assertRaises(KeyError):
            extract_settings_from_op_metadata(op_metadata_faulty_dict,
                                              'OIDC_OP_AUTHORIZATION_ENDPOINT')

    def test_extract_settings_from_op_metadata_incorrect_configuration(self):
        """
        Testing 'ImproperlyConfigured' is raised if we pass some setting which
        is not configured
        """
        op_metadata_sample_dict = {
            'authorization_endpoint': 'test_auth',
            'token_endpoint': 'test_token',
            'userinfo_endpoint': 'test_userinfo',
            'jwks_uri': 'test_jwks'
        }
        with self.assertRaises(ImproperlyConfigured):
            extract_settings_from_op_metadata(op_metadata_sample_dict, 'test')


class GetFromOPMetadataTestCase(TestCase):

    @override_settings(OIDC_OP_METADATA_ENDPOINT='test_metadata_url')
    @patch('mozilla_django_oidc.utils.extract_settings_from_op_metadata')
    @patch('mozilla_django_oidc.utils.get_op_metadata')
    def test_get_from_op_metadata(self, get_op_metadata_patch,
                                  extract_settings_from_op_metadata_patch):
        """Testing that caching is happening properly."""
        get_op_metadata_patch.return_value = 'test_metadata'
        extract_settings_from_op_metadata_patch.return_value = 'test_value'

        self.assertEqual(get_from_op_metadata('test_attr'), 'test_value')
        # By default local memory cache will be used.
        self.assertEqual(cache.get(OIDCCacheKey.OP_METADATA.value), 'test_metadata')

    @override_settings(OIDC_OP_METADATA_ENDPOINT='test_metadata_url')
    @patch('mozilla_django_oidc.utils.extract_settings_from_op_metadata')
    @patch('mozilla_django_oidc.utils.get_op_metadata')
    def test_get_from_op_metadata_already_cached(self, get_op_metadata_patch,
                                                 extract_settings_from_op_metadata_patch):
        """Testing that cached value must be used if exists."""
        cache.set(OIDCCacheKey.OP_METADATA.value, 'test_metadata')
        get_op_metadata_patch.side_effect = Exception("It should not be called")
        extract_settings_from_op_metadata_patch.return_value = 'test_value'

        self.assertEqual(get_from_op_metadata('test_attr'), 'test_value')
        extract_settings_from_op_metadata_patch.\
            assert_called_once_with('test_metadata', 'test_attr')
