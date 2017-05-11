============
Installation
============

At the command line::

    $ pip install mozilla-django-oidc


Quick start
===========

After installation, you'll need to do some things to get your site using
``mozilla-django-oidc``.


Acquire a client id and client secret
-------------------------------------

Before you can configure your application, you need to set up a client with an
OpenID Connect provider (OP).

You'll need to set up a *different client* for every environment you have for
your site. For example, if your site has a -dev, -stage, and -prod environments,
each of those has a different hostname and thus you need to set up a separate
client for each one.

You need to provide your OpenID Connect provider (OP) the callback url for your
site. The URL path for the callback url is ``/oidc/callback/``.

Here are examples of callback urls:

* ``http://127.0.0.1:8000/oidc/callback/`` -- for local development
* ``https://myapp-dev.example.com/oidc/callback/`` -- -dev environment for myapp
* ``https://myapp.herokuapps.com/oidc/callback/`` -- my app running on Heroku

The OpenID Connect provider (OP) will then give you the following:

1. a client id (``OIDC_OP_CLIENT_ID``)
2. a client secret (``OIDC_OP_CLIENT_SECRET``)

You'll need these values for settings.


Add settings to settings.py
---------------------------

Start by making the following changes to your ``settings.py`` file.

.. code-block:: python

   # Add 'mozilla_django_oidc' to INSTALLED_APPS
   INSTALLED_APPS = (
       # ...
       'django.contrib.auth',
       'mozilla_django_oidc',  # Load after auth
       # ...
   )

   # Add 'mozilla_django_oidc' authentication backend
   AUTHENTICATION_BACKENDS = (
       # ...
       'django.contrib.auth.backends.ModelBackend',
       'mozilla_django_oidc.auth.OIDCAuthenticationBackend',
       # ...
   )

You also need to configure some OpenID Connect related settings too.

These values come from your OpenID Connect provider (OP).

.. code-block:: python

   OIDC_OP_CLIENT_ID = os.environ['OIDC_OP_CLIENT_ID']
   OIDC_OP_CLIENT_SECRET = os.environ['OIDC_OP_CLIENT_SECRET']


.. warning::
   The OpenID Connect provider (OP) provided client id and secret are secret
   values.

   **DON'T** check them into version control--pull them in from the environment.

   If you ever accidentally check them into version control, contact your OpenID
   Connect provider (OP) as soon as you can, disable that set of client id and
   secret, and generate a new set.


These values are specific to your OpenID Connect provider (OP)--consult their
documentation for the appropriate values.

.. code-block:: python

   OIDC_OP_AUTHORIZATION_ENDPOINT = "<URL of the OIDC OP authorization endpoint>"
   OIDC_OP_TOKEN_ENDPOINT = "<URL of the OIDC OP token endpoint>"
   OIDC_OP_USER_ENDPOINT = "<URL of the OIDC OP userinfo endpoint>"


This value depends on your site.

.. code-block:: python

   SITE_URL = "<FQDN that users access the site from eg. http://127.0.0.1:8000/ >"


.. warning::
   Don't use Django's cookie-based sessions because they might open you up to
   replay attacks.

   You can find more info about `cookie-based sessions`_ in Django's documentation.

.. _cookie-based sessions: https://docs.djangoproject.com/en/1.10/topics/http/sessions/#using-cookie-based-sessions


Add routing to urls.py
----------------------

Next, edit your ``urls.py`` and add the following:

.. code-block:: python

   urlpatterns = patterns(
       # ...
       url(r'^oidc/', include('mozilla_django_oidc.urls')),
       # ...
   )


Add login link to templates
---------------------------

Then you need to add the login link to your templates. The view name is
``oidc_authentication_init``.

Django templates example:

.. code-block:: html+django

   <html>
     <body>
       {% if user.is_authenticated %}
         <p>Current user: {{ user.email }}</p>
       {% else %}
         <a href="{% url 'oidc_authentication_init' %}">Login</a>
       {% endif %}
     </body>
   </html>


Jinja2 templates example:

.. code-block:: html+jinja2

   <html>
     <body>
       {% if user.is_authenticated() %}
         <p>Current user: {{ user.email }}</p>
       {% else %}
         <a href="{% url('oidc_authentication_init') %}">Login</a>
       {% endif %}
     </body>
   </html>


Additional optional configuration
=================================

Validate ID tokens by renewing them
-----------------------------------

Users log into your site by authenticating with an OIDC provider. While the user
is doing things on your site, it's possible that the account that the user used
to authenticate with the OIDC provider was disabled. A classic example of this
is when a user quits his/her job and their LDAP account is disabled.

However, even if that account was disabled, the user's account and session on
your site will continue. In this way, a user can quit his/her job, lose access to
his/her corporate account, but continue to use your website.

To handle this scenario, your website needs to know if the user's ID token with
the OIDC provider is still valid. You need to use the
:py:class:`mozilla_django_oidc.contrib.auth0.middleware.RefreshIDToken` middleware.

To add it to your site, put it in the settings::

    MIDDLEWARE_CLASSES = [
        # middleware involving session and autheentication must come first
        # ...
        'mozilla_django_oidc.contrib.auth0.middleware.RefreshIDToken',
        # ...
    ]


The ``RefreshIDToken`` middleware will check that the id token is still valid
with the OIDC provider every ``settings.OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS``
which defaults to 15 minutes.

.. note::
   Currently, this is implemented using an Auth0-specific API endpoint. That
   will change soon.


Connecting OIDC user identities to Django users
-----------------------------------------------

By default, mozilla-django-oidc looks up a Django user matching the email field
to the email address returned in the user info data from the OIDC provider.

This means that no two users in the Django user table can have the same email
address. Since the email field is not unique, it's possible that this can
happen. Especially if you allow users to change their email address. If it ever
happens, then the users in question won't be able to authenticate.

If you want different behavior, subclass the
:py:class:`mozilla_django_oidc.auth.OIDCAuthenticationBackend` class and
override the `filter_users_by_claims` method.

For example, let's say we store the email address in a ``Profile`` table
in a field that's marked unique so multiple users can't have the same
email address. Then we could do this:

.. code-block:: python

   from mozilla_django_oidc.auth import OIDCAuthenticationBackend

   class MyOIDCAB(OIDCAuthenticationBackend):
       def filter_users_by_claims(self, claim):
           email = claims.get('email')
           if not email:
               return self.UserModel.objects.none()

           try:
               profile = Profile.objects.get(email=email)
               return profile.user

           except Profile.DoesNotExist:
               return self.UserModel.objects.none()


Then you'd use the Python dotted path to that class in the
``settings.AUTHENTICATION_BACKENDS`` instead of
``mozilla_django_oidc.auth.OIDCAuthenticationBackend``.


Creating a Django ``User`` record for new users
-----------------------------------------------

If a user logs into your site and doesn't already have an account, by default,
mozilla-django-oidc will create a new Django user account. It will create the
``User`` instance filling in the username (hash of the email address) and email
fields.

If you want something different, set ``settings.OIDC_USERNAME_ALGO`` to a Python
dotted path to the function you want to use.

The function takes in an email address as a text (Python 2 unicode or Python 3
string) and returns a text (Python 2 unicode or Python 3 string).

Here's an example function for Python 3 and Django 1.11 that doesn't convert
the email address at all:

.. code-block:: python

   import unicodedata

   def generate_username(email):
       # Using Python 3 and Django 1.11, usernames can contain alphanumeric
       # (ascii and unicode), _, @, +, . and - characters. So we normalize
       # it and slice at 150 characters.
       return unicodedata.normalize('NFKC', email)[:150]


.. seealso::

   Django 1.8 username:
       https://docs.djangoproject.com/en/1.8/ref/contrib/auth/#django.contrib.auth.models.User.username

   Django 1.9 username:
       https://docs.djangoproject.com/en/1.9/ref/contrib/auth/#django.contrib.auth.models.User.username

   Django 1.10 username:
       https://docs.djangoproject.com/en/1.10/ref/contrib/auth/#django.contrib.auth.models.User.username

   Django 1.11 username:
       https://docs.djangoproject.com/en/1.11/ref/contrib/auth/#django.contrib.auth.models.User.username


If your website needs to do other bookkeeping things when a new ``User`` record
is created, then you should subclass the
:py:class:`mozilla_django_oidc.auth.OIDCAuthenticationBackend` class and
override the `create_user` method.

For example, let's say you want to populate the ``User`` instance with other
data from the claims:

.. code-block:: python

   from mozilla_django_oidc.auth import OIDCAuthenticationBackend
   from myapp.models import Profile

   class MyOIDCAB(OIDCAuthenticationBackend):
       def create_user(self, claims):
           user = super(OIDCAuthenticationRequestView, self).create_user(claims)

           user.first_name = claim.get('given_name', '')
           user.last_name = claim.get('family_name', '')

           return user


Then you'd use the Python dotted path to that class in the
``settings.AUTHENTICATION_BACKENDS`` instead of
``mozilla_django_oidc.auth.OIDCAuthenticationBackend``.


.. seealso::

   https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
