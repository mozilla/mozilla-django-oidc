.. :changelog:

History
-------

development
++++++++++++++++++


Bugs:

* Use ``settings.OIDC_VERIFY_SSL`` also when validating the token.
  Thanks `@GermanoGuerrini`_

.. _`@GermanoGuerrini`: https://github.com/GermanoGuerrini

0.3.1 (2017-06-15)
++++++++++++++++++

Security issues:

* **Medium**: Sanitize next url for authentication view

0.3.0 (2017-06-13)
++++++++++++++++++

Security issues:

* **Low**: Logout using POST not GET (#126)

Backwards-incompatible changes:

* The ``settings.SITE_URL`` is no longer used. Instead the absolute URL is
  derived from the request's ``get_host()``.
* Only log out by HTTP POST allowed.

Bugs:

* Test suite maintenance (#108, #109, #142)

0.2.0 (2017-06-07)
++++++++++++++++++

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
++++++++++++++++++

* First release on PyPI.
