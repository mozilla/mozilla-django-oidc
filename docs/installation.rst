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
