import sys

try:
    from django.conf import settings
    from django.test.utils import get_runner

    settings.configure(
        DEBUG=True,
        USE_TZ=True,
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
            }
        },
        ROOT_URLCONF='mozilla_django_oidc.urls',
        INSTALLED_APPS=[
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sites',
            'mozilla_django_oidc',
        ],
        SITE_ID=1,
        SITE_URL='http://example.com',
        MIDDLEWARE_CLASSES=(),
        OIDC_USERNAME_ALGO=None
    )

    try:
        import django
        setup = django.setup
    except AttributeError:
        pass
    else:
        setup()

except ImportError:
    import traceback
    traceback.print_exc()
    msg = 'To fix this error, run: pip install -r requirements/requirements_test.txt'
    raise ImportError(msg)


def run_tests(*test_args):
    if not test_args:
        test_args = ['tests']

    test_runner = get_runner(settings)()
    failures = test_runner.run_tests(test_args)

    if failures:
        sys.exit(bool(failures))


if __name__ == '__main__':
    run_tests(*sys.argv[1:])
