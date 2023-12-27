========
Settings
========

This document describes the Django settings that can be used to customize the configuration
of ``mozilla-django-oidc``.

.. py:attribute:: OIDC_OP_AUTHORIZATION_ENDPOINT

   :default: No default

   URL of your OpenID Connect provider authorization endpoint.

.. py:attribute:: OIDC_OP_TOKEN_ENDPOINT

   :default: No default

   URL of your OpenID Connect provider token endpoint

.. py:attribute:: OIDC_OP_USER_ENDPOINT

   :default: No default

   URL of your OpenID Connect provider userinfo endpoint

.. py:attribute:: OIDC_OP_JWKS_ENDPOINT

   :default: No default

   URL of your OpenID Connect provider JWKS (JSON Web Key Sets) endpoint.
   Used in JWT verification with PKI when ``OIDC_RP_IDP_SIGN_KEY`` is not
   provided.

.. py:attribute:: OIDC_RP_CLIENT_ID

   :default: No default

   OpenID Connect client ID provided by your OP

.. py:attribute:: OIDC_RP_CLIENT_SECRET

   :default: No default

   OpenID Connect client secret provided by your OP

.. py:attribute:: OIDC_VERIFY_JWT

   :default: ``True``

   Controls whether the OpenID Connect client verifies the signature of the JWT tokens

.. py:attribute:: OIDC_VERIFY_KID

    :default: ``True``

    Controls whether the OpenID Connect client verifies the KID field of the JWT tokens

.. py:attribute:: OIDC_USE_NONCE

   :default: ``True``

   Controls whether the OpenID Connect client uses nonce verification

.. py:attribute:: OIDC_VERIFY_SSL

   :default: ``True``

   Controls whether the OpenID Connect client verifies the SSL certificate of the OP responses

.. py:attribute:: OIDC_TIMEOUT

   :default: ``None``

   Defines a timeout for all requests to the OpenID Connect provider (fetch JWS,
   retrieve JWT tokens, Userinfo Endpoint). The default is set to `None` which means
   the library will wait indefinitely. The time can be defined as seconds (integer).
   More information about possible configuration values, see Python `requests`:
   https://requests.readthedocs.io/en/master/user/quickstart/#timeouts

.. py:attribute:: OIDC_PROXY

   :default: ``None``

    Defines a proxy for all requests to the OpenID Connect provider (fetch JWS,
    retrieve JWT tokens, Userinfo Endpoint). The default is set to `None` which means
    the library will not use a proxy and connect directly. For configuring a proxy
    check the Python `requests` documentation:
    https://requests.readthedocs.io/en/master/user/advanced/#proxies

.. py:attribute:: OIDC_EXEMPT_URLS

   :default: ``[]``

   This is a list of absolute url paths, regular expressions for url paths,  or
   Django view names. This plus the mozilla-django-oidc urls are exempted from
   the session renewal by the ``SessionRefresh`` middleware.

.. py:attribute:: OIDC_CREATE_USER

   :default: ``True``

   Enables or disables automatic user creation during authentication

 .. py:attribute:: OIDC_USERNAME_ALGO

   :default: ``None``

   It enables using a custom method to generate the django username from the user's
   email and OIDC claims.

.. py:attribute:: OIDC_STATE_SIZE

   :default: ``32``

   Sets the length of the random string used for OpenID Connect state verification

.. py:attribute:: OIDC_NONCE_SIZE

   :default: ``32``

   Sets the length of the random string used for OpenID Connect nonce verification

.. py:attribute:: OIDC_MAX_STATES

   :default: ``50``

   Sets the maximum number of State / Nonce combinations stored in the session.
   Multiple combinations are used when the user does multiple concurrent login sessions.

.. py:attribute:: OIDC_REDIRECT_FIELD_NAME

   :default: ``next``

   Sets the GET parameter that is being used to define the redirect URL after succesful authentication

.. py:attribute:: OIDC_CALLBACK_CLASS

   :default: ``mozilla_django_oidc.views.OIDCAuthenticationCallbackView``

   Allows you to substitute a custom class-based view to be used as OpenID Connect
   callback URL.

   .. note::

      When using a custom callback view, it is generally a good idea to subclass the
      default ``OIDCAuthenticationCallbackView`` and override the methods you want to change.

.. py:attribute:: OIDC_AUTHENTICATE_CLASS

   :default: ``mozilla_django_oidc.views.OIDCAuthenticationRequestView``

   Allows you to substitute a custom class-based view to be used as OpenID Connect
   authenticate URL.

   .. note::

      When using a custom authenticate view, it is generally a good idea to subclass the
      default ``OIDCAuthenticationRequestView`` and override the methods you want to change.

.. py:attribute:: OIDC_RP_SCOPES

   :default: ``openid email``

   The OpenID Connect scopes to request during login.

   .. warning::

      When using custom scopes consider overriding the :ref:`claim verification method <advanced_claim_verification>`
      since the default one only works for the default ``mozilla-django-oidc`` configuration.

.. py:attribute:: OIDC_STORE_ACCESS_TOKEN

   :default: ``False``

   Controls whether the OpenID Connect client stores the OIDC ``access_token`` in the user session.
   The session key used to store the data is ``oidc_access_token``.

   By default we want to store as few credentials as possible so this feature defaults to ``False``
   and it's use is discouraged.

   .. warning::
      This feature stores authentication information in the session. If used in combination with Django's
      cookie-based session backend, those tokens will be visible in the browser's cookie store.

.. py:attribute:: OIDC_STORE_ID_TOKEN

   :default: ``False``

   Controls whether the OpenID Connect client stores the OIDC ``id_token`` in the user session.
   The session key used to store the data is ``oidc_id_token``.

.. py:attribute:: OIDC_AUTH_REQUEST_EXTRA_PARAMS

   :default: `{}`

   Additional parameters to include in the initial authorization request.

.. py:attribute:: OIDC_RP_SIGN_ALGO

   :default: ``HS256``

   Sets the algorithm the IdP uses to sign ID tokens.

.. py:attribute:: OIDC_RP_IDP_SIGN_KEY

   :default: ``None``

   Sets the key the IdP uses to sign ID tokens in the case of an RSA sign algorithm.
   Should be the signing key in PEM or DER format.

.. py:attribute:: LOGIN_REDIRECT_URL

   :default: ``/accounts/profile``

   Path to redirect to on successful login. If you don't specify this, the
   default Django value will be used.

   .. seealso::

      https://docs.djangoproject.com/en/stable/ref/settings/#login-redirect-url

.. py:attribute:: LOGIN_REDIRECT_URL_FAILURE

   :default: ``/``

   Path to redirect to on an unsuccessful login attempt.

.. py:attribute:: LOGOUT_REDIRECT_URL

   :default: ``None``

   After the logout view has logged the user out, it redirects to this url path.

   .. seealso::

      https://docs.djangoproject.com/en/stable/ref/settings/#logout-redirect-url

.. py:attribute:: OIDC_OP_LOGOUT_URL_METHOD

   :default: ``''`` (will use ``LOGOUT_REDIRECT_URL``)

   Function path that returns a URL to redirect the user to after
   ``auth.logout()`` is called.

   .. versionchanged:: 0.7.0
      The function must now take a ``request`` parameter.

.. py:attribute:: OIDC_AUTHENTICATION_CALLBACK_URL

   :default: ``oidc_authentication_callback``

   URL pattern name for ``OIDCAuthenticationCallbackView``. Will be passed to ``reverse``.
   The pattern can also include namespace in order to resolve included urls.

   .. seealso::

      https://docs.djangoproject.com/en/stable/topics/http/urls/#url-namespaces

.. py:attribute:: OIDC_ALLOW_UNSECURED_JWT

   :default: ``False``

   Controls whether the authentication backend is going to allow unsecured JWT tokens (tokens with header ``{"alg":"none"}``).
   This needs to be set to ``True`` if OP is returning unsecured JWT tokens and RP wants to accept them.

   .. seealso::

      https://tools.ietf.org/html/rfc7519#section-6

.. py:attribute:: OIDC_TOKEN_USE_BASIC_AUTH

   :default: False

   Use HTTP Basic Authentication instead of sending the client secret in token request POST body.

.. py:attribute:: ALLOW_LOGOUT_GET_METHOD

   :default: False

   Allow using GET method to logout user

.. py:attribute:: OIDC_USE_PKCE

   :default: ``False``

   Controls whether the authentication backend uses PKCE (Proof Key For Code Exchange) during the authorization code flow.

   .. seealso::

      https://datatracker.ietf.org/doc/html/rfc7636

.. py:attribute:: OIDC_PKCE_CODE_CHALLENGE_METHOD

   :default: ``S256``

   Sets the method used to generate the PKCE code challenge.

   Supported methods are:

   * **plain**:
      ``code_challenge = code_verifier``

   * **S256**:
      ``code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))``

   .. note::

      This only has an effect if ``OIDC_USE_PKCE`` is ``True``.

   .. seealso::

      https://datatracker.ietf.org/doc/html/rfc7636#section-4.2

.. py:attribute:: OIDC_PKCE_CODE_VERIFIER_SIZE

   :default: ``64``

   Sets the length of the random string used for the PKCE code verifier.  Must be between ``43`` and ``128`` inclusive.

   .. note::

      This only has an effect if ``OIDC_USE_PKCE`` is ``True``.

   .. seealso::

      https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
