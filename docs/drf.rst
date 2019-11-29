=======================================
DRF (Django REST Framework) integration
=======================================

If you want DRF to authenticate users based on an OAuth access token provided in
the ``Authorization`` header, you can use the DRF-specific authentication class
which ships with the package.

Add this to your settings:

.. code-block:: python

    REST_FRAMEWORK = {
        'DEFAULT_AUTHENTICATION_CLASSES': [
            'mozilla_django_oidc.contrib.drf.OIDCAuthentication',
            'rest_framework.authentication.SessionAuthentication',
            # other authentication classes, if needed
        ],
    }

Note that this only takes care of authenticating against an access token, and
provides no options to create or renew tokens.

If you've created a custom Django ``OIDCAuthenticationBackend`` and added that
to your ``AUTHENTICATION_BACKENDS``, the DRF class should be smart enough to
figure that out. Alternatively, you can manually set the OIDC backend to use:

.. code-block:: python

	OIDC_DRF_AUTH_BACKEND = 'mozilla_django_oidc.auth.OIDCAuthenticationBackend'
