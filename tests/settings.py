SECRET_KEY = 'can you keep a secret?'

DEBUG = True

USE_TZ = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
    }
}

ROOT_URLCONF = 'mozilla_django_oidc.urls'

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sites',
    'mozilla_django_oidc',
]

SITE_ID = 1

SITE_URL = 'http://example.com'

MIDDLEWARE_CLASSES = ()

OIDC_USERNAME_ALGO = None
