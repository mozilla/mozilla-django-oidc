from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings
from django.test.client import RequestFactory

from mozilla_django_oidc.utils import absolutify, import_from_settings


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
