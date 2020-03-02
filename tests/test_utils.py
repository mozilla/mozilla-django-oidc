from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings
from django.test.client import RequestFactory

from mozilla_django_oidc.utils import absolutify, add_state_and_nonce_to_session, import_from_settings


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


class SessionStateTestCase(TestCase):

    def setUp(self) -> None:
        self.request = RequestFactory().get('/doesnt/matter')

        # Setup request with a session for testing
        middleware = SessionMiddleware()
        middleware.process_request(self.request)
        self.request.session.save()

    def test_add_state_to_session(self):
        state = 'example_state'
        params = {}

        add_state_and_nonce_to_session(self.request, state, params)

        self.assertIn('nonce', params)
        self.assertIn('oidc_states', self.request.session)
        self.assertEqual(1, len(self.request.session['oidc_states']))
        self.assertIn(state, self.request.session['oidc_states'].keys())

    def test_existing_params(self):
        state = 'example_state'

        param_key = 'example_param'
        params = {
            param_key: 'example',
        }

        add_state_and_nonce_to_session(self.request, state, params)

        self.assertIn('nonce', params)
        self.assertIn(param_key, params)

    def test_multiple_states(self):
        state1 = 'example_state_1'
        state2 = 'example_state_2'
        params = {}

        add_state_and_nonce_to_session(self.request, state1, params)

        self.assertEqual(1, len(self.request.session['oidc_states']))
        self.assertIn(state1, self.request.session['oidc_states'].keys())

        add_state_and_nonce_to_session(self.request, state2, params)

        self.assertEqual(2, len(self.request.session['oidc_states']))
        self.assertIn(state1, self.request.session['oidc_states'].keys())
        self.assertIn(state2, self.request.session['oidc_states'].keys())

    def test_max_states(self):
        limit = import_from_settings('OIDC_MAX_OIDC_STATES', 50)

        first_state = 'example_state_0'
        params = {}
        for i in range(limit):
            state = 'example_state_{}'.format(i)
            add_state_and_nonce_to_session(self.request, state, params)

        self.assertEqual(limit, len(self.request.session['oidc_states']))
        self.assertIn(first_state, self.request.session['oidc_states'])

        # Add another state which should remove the very first one
        additional_state = 'example_state'
        add_state_and_nonce_to_session(self.request, additional_state, params)

        # Make sure the oldest state was deleted
        self.assertNotIn(first_state, self.request.session['oidc_states'])

        # New state should be in the list but length should not have changed
        self.assertEqual(limit, len(self.request.session['oidc_states']))
        self.assertIn(additional_state, self.request.session['oidc_states'].keys())

    @override_settings(OIDC_USE_NONCE=False)
    def test_state_dictionary_without_nonce_format(self):
        state = 'example_state'
        params = {}

        add_state_and_nonce_to_session(self.request, state, params)

        # Test state dictionary
        self.assertIn(state, self.request.session['oidc_states'].keys())
        self.assertTrue(isinstance(self.request.session['oidc_states'][state], dict))

        # Test nonce
        self.assertEqual(self.request.session['oidc_states'][state]['nonce'], None)

        # Test added_on timestamp
        self.assertTrue(isinstance(self.request.session['oidc_states'][state]['added_on'], float))

    def test_state_dictionary_with_nonce_format(self):
        state = 'example_state'
        params = {}

        add_state_and_nonce_to_session(self.request, state, params)

        self.assertTrue(isinstance(self.request.session['oidc_states'][state]['nonce'], str))
