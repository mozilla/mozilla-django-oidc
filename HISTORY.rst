.. :changelog:

History
-------

4.0.1 (2024-03-12)
==================

* Update configuration for readthedocs.
* Point HEAD to main branch.
* Update project's README file.


4.0.0 (2024-01-11)
==================

* Added PKCE support in the authorization code flow.
  Thanks `@themooer1 <https://github.com/themooer1>`_ and `@escattone <https://github.com/escattone/>`_
* Added support for Elliptic Curve JWT signing algorithms
  Thanks `@atanunq <https://github.com/atanunq>`_
* Replace mock with unittest.mock
  Thanks `@traylenator <https://github.com/traylenator>`_
* Add pre-commit hooks
* Add support for Python 3.11 and 3.12
* Add support for Django 4.2
* Document OIDC_USERNAME_ALGO
  Thanks `@polyccon <https://github.com/polyccon>`_
* Add claims to custom username algorithm
  Thanks `@EduardRosert <https://github.com/EduardRosert>`_
* Formatting fixes in the Documentation
  Thanks `@EduardRosert <https://github.com/EduardRosert>`_
* Update token error response handling
  Thanks `@dopry <https://github.com/dopry>`

Backwards-incompatible changes:

* Drop Python 3.7 support
* Drop Django 4.1 support


3.0.0 (2022-11-14)
==================
* Gracefully handle ``www-authenticate`` header with missing ``error_description``.
  Thanks `@vinitsharswat <https://github.com/vinitsharswat>`_ and `@adamj9431 <https://github.com/adamj9431>`_
* Lint project with ``black``.
* Add support for Django 4
* Document OIDC_OP_JWKS_ENDPOINT.
  Thanks `@yoctozepto <https://github.com/yoctozepto>`_
* Update typo in comments.
  Thanks `@rabbit-aaron <https://github.com/rabbit-aaron>`_
* LOGIN_REDIRECT_URL now accepts a named url pattern.
  Thanks `@dispiste <https://github.com/dispiste>`_
* Pass `OIDC_AUTH_REQUEST_EXTRA_PARAMS` to SessionRefresh
  Thanks `@melanger <https://github.com/melanger>`_
* Remove state from from session after failed authentication attempts
  Thanks `@cfra <https://github.com/cfra>`_
* Do not call auth.login() on session refresh.
  Thanks `crgwbr <https://github.com/crgwbr>`_

Backwards-incompatible changes:

* Drop Python 3.6 support
* Drop Django 2.x Support
* Drop Django 3.1 support


2.0.0 (2021-07-27)
==================

* Make `get_or_create_user` compatible with custom scope configuration
  by moving scope specific code to `describe_user_by_claims`
  Thanks `@cfra <https://github.com/cfra>`_
* Add support for Django 3.2
  Thanks `@jannh <https://github.com/jannh>`_
* Add configuration to opt in logout using GET
* Fix url encoding using escaped space characters
* Pass email as named argument in create_user
* Do not fail if JWK does not have a key ID
  Thanks `@cfra <https://github.com/cfra>`_
* Update middleware init to configure settings
  Thanks `@dreynolds <https://github.com/dreynolds>`_
* Add SessionAuthentication to DRF auth class
  Thanks `@SpyTec <https://github.com/SpyTec>`_

Backwards-incompatible changes:

* Drop Django 1.x support
* Drop Python2 support


1.2.4 (2020-08-19)
==================

* Fix error in README.rst
  Thanks `@der-gabe <https://github.com/der-gabe>`_
* Fix JWKS handling when the same `kid` value is used across JWKs with
  different `alg` specified
  Thanks `@davidjb <https://github.com/davidjb>`_
* Support regex patterns in ``OIDC_EXEMPT_URLS``, to allow exempting session refreshes in
  ``SessionMiddleware`` for URLs matching the pattern
  Thanks `@jwhitlock <https://github.com/jwhitlock>`_
* Move nonce outside of add_state_and_noce_to_session method.
* Change log level to info for the add_state_and_verifier_and_nonce_to_session.
* Session save/load management
  Thanks `@Flor1an-dev <https://github.com/Flor1an-dev>`_
* Allow multiple parallel login sessions
  Thanks `@istreeter <https://github.com/istreeter>`_

.. _`@jwhitlock`: https://github.com/jwhitlock

1.2.3 (2020-01-02)
===================

* Add support for Django 3.x
  Thanks `@jaap3 <https://github.com/jaap3>`_
* Use new E2E testing images from mozilla namespace
* Remove support for EOL'ed Django versions

1.2.2 (2019-04-18)
===================

* Add Mozilla code of conduct
* Allow overriding OIDC settings per class

1.2.1 (2019-01-22)
===================

* Make `verify_claims` compatible with custom scope configuration.

1.2.0 (2019-01-09)
==================

* Improve travis automation for PyPI releases
* Allow basic auth for OIDC token endpoint requests
  Thanks `@anttipalola <https://github.com/anttipalola>`_
* Replace phantomjs with firefox headless for e2e testing
* Add default email verification claim check
  Thanks `@kerrermanisNL <https://github.com/kerrermanisNL>`_
* Remove compatibility code for unsupported Django versions
* Add settings to control redirect behavior
  Thanks `@chrisbrantley <https://github.com/chrisbrantley>`_

1.1.2 (2018-08-24)
===================

* Fix JWKS handling when OP returns multiple keys
  Thanks `@JustinAzoff <https://github.com/JustinAzoff>`_


1.1.1 (2018-08-09)
===================

* Fix `is_safe_url` on Django 2.1
* Fix signature in `authenticate` method to be compatible with Django 2.1
* Remove legacy code for unsupported Django < 1.11
  Thanks `@SirTyson <https://github.com/SirTyson>`_


1.1.0 (2018-08-02)
===================

* Installation doc fixes
  Thanks `@mklan <https://github.com/mklan>`_
* Drop support for unsupported Django 1.8 and Python 3.3.
* Refactor authentication backend to make it easier to extend
  Required by DRF support feature.
* Add DRF support
  Thanks `@anlutro <https://github.com/anlutro>`_
* Improve local docker environment setup
* Add flag to allow using unsecured tokens
* Allow using JWK with optional ``alg``
  Thanks `@Algogator <https://github.com/Algogator>`_


1.0.0 (2018-05-09)
===================

* Add OIDC_AUTHENTICATION_CALLBACK_URL as a new configuration parameter
* Fail earlier when JWS algorithm does not OIDC_RP_SIGN_ALGO.
  Thanks `@anlutro <https://github.com/anlutro>`_
* RS256 verification through ``settings.OIDC_OP_JWKS_ENDPOINT``
  Thanks `@GermanoGuerrini <https://github.com/GermanoGuerrini>`_
* Refactor OIDCAuthenticationBackend so that token retrieval methods can be overridden in a subclass when you need to.

Backwards-incompatible changes:

* ``OIDC_OP_LOGOUT_URL_METHOD`` takes a ``request`` parameter now.
* Changed name of ``RefreshIDToken`` middleware to ``SessionRefresh``.


.. _`@anlutro`: https://github.com/anlutro

0.6.0 (2018-03-27)
===================

* Add e2e tests and automation
* Add caching for exempt URLs
* Fix logout when session refresh fails

0.5.0 (2018-01-10)
===================

* Add Django 2.0 support
* Fix tox configuration

Backwards-incompatible changes:

* Drop Django 1.10 support

0.4.2 (2017-11-29)
===================

* Fix OIDC_USERNAME_ALGO to actually load dotted import path of callback.
* Add verify_claims method for advanced authentication checks

0.4.1 (2017-10-25)
===================

* Send bytes to josepy. Fixes python3 support.

0.4.0 (2017-10-24)
===================

Security issues:

* **High**: Replace python-jose with josepy and use pyca/cryptography instead of pycrypto (CVE-2013-7459).

Backwards-incompatible changes:

* ``OIDC_RP_IDP_SIGN_KEY`` no longer uses the JWK json as ``dict`` but PEM or DER keys instead.


0.3.2 (2017-10-03)
===================

Features:

* Implement RS256 verification
  Thanks `@puiterwijk <https://github.com/puiterwijk>`_

Bugs:

* Use ``settings.OIDC_VERIFY_SSL`` also when validating the token.
  Thanks `@GermanoGuerrini <https://github.com/GermanoGuerrini>`_
* Make OpenID Connect scope configurable.
  Thanks `@puiterwijk <https://github.com/puiterwijk>`_
* Add path host injection unit-test (#171)
* Revisit OIDC_STORE_{ACCESS,ID}_TOKEN config entries
* Allow configuration of additional auth parameters


.. _`@GermanoGuerrini`: https://github.com/GermanoGuerrini
.. _`@puiterwijk`: https://github.com/puiterwijk

0.3.1 (2017-06-15)
===================

Security issues:

* **Medium**: Sanitize next url for authentication view

0.3.0 (2017-06-13)
===================

Security issues:

* **Low**: Logout using POST not GET (#126)

Backwards-incompatible changes:

* The ``settings.SITE_URL`` is no longer used. Instead the absolute URL is
  derived from the request's ``get_host()``.
* Only log out by HTTP POST allowed.

Bugs:

* Test suite maintenance (#108, #109, #142)

0.2.0 (2017-06-07)
===================

Backwards-incompatible changes:

* Drop support for Django 1.9 (#130)

  If you're using Django 1.9, you should update Django first.

* Move middleware to ``mozilla_django_oidc.middleware`` and
  change it to use authentication endpoint with ``prompt=none`` (#94)

  You'll need to update your ``MIDDLEWARE_CLASSES``/``MIDDLEWARE``
  setting accordingly.

* Remove legacy ``base64`` handling of OIDC secret. Now RP secret
  should be plaintext.

Features:

* Add support for Django 1.11 and Python 3.6 (#85)
* Update middleware to work with Django 1.10+ (#90)
* Documentation updates
* Rework test infrastructure so it's tox-based (#100)

Bugs:

* always decode verified token before ``json.load()`` (#116)
* always redirect to logout_url even when logged out (#121)
* Change email matching to be case-insensitive (#102)
* Allow combining OIDCAuthenticationBackend with other backends (#87)
* fix is_authenticated usage for Django 1.10+ (#125)

0.1.0 (2016-10-12)
===================

* First release on PyPI.
