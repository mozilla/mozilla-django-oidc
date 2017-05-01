============
Installation
============

At the command line::

    $ pip install mozilla-django-oidc

.. _cookie-based sessions: https://docs.djangoproject.com/en/1.10/topics/http/sessions/#using-cookie-based-sessions

.. warning::
   We highly recommend to avoid using Django's cookie-based sessions because they might open you up to replay attacks.

.. note::
   You can find more info about `cookie-based sessions`_ in Django's documentation.

Quick start
===========

After installation, you'll need to configure your site to use ``mozilla-django-oidc``.
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

Next, edit your ``urls.py`` and add the following:

.. code-block:: python

   urlpatterns = patterns(
       # ...
       url(r'^oidc/', include('mozilla_django_oidc.urls')),
       # ...
   )

Then you need to add the login link to your Django templates. For example:

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

You also need to configure some OpenID connect related settings too.
Please add the following to your ``settings.py``:

.. code-block:: python

   OIDC_OP_AUTHORIZATION_ENDPOINT = "<URL of the OIDC OP authorization endpoint>"
   OIDC_OP_TOKEN_ENDPOINT = "<URL of the OIDC OP token endpoint>"
   OIDC_OP_USER_ENDPOINT = "<URL of the OIDC OP userinfo endpoint>"
   OIDC_OP_CLIENT_ID = "<OP issued client id>"
   OIDC_OP_CLIENT_SECRET = "<OP issued client secret>"
   SITE_URL = "<FQDN that users access the site from eg. http://127.0.0.1:8000/ >"

Finally let your OpenID connect OP know about your callback URL. In our example this is:
``http://127.0.0.1:8000/oidc/callback/``.


Additional optional configuration
=================================

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
