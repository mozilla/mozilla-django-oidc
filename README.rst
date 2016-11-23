=============================
mozilla-django-oidc
=============================

.. image:: https://badge.fury.io/py/mozilla-django-oidc.png
    :target: https://badge.fury.io/py/mozilla-django-oidc

.. image:: https://travis-ci.org/mozilla/mozilla-django-oidc.png?branch=master
    :target: https://travis-ci.org/mozilla/mozilla-django-oidc

.. image:: https://img.shields.io/codecov/c/github/mozilla/mozilla-django-oidc.svg
   :target: https://codecov.io/gh/mozilla/mozilla-django-oidc

A lightweight authentication and access management library for integration with OpenID Connect enabled authentication services.

Documentation
-------------

The full documentation is at https://mozilla-django-oidc.readthedocs.io.

Running Tests
--------------

Does the code actually work?

::

    source <YOURVIRTUALENV>/bin/activate
    (myenv) $ pip install -r requirements/requirements_test.txt
    (myenv) $ python runtests.py

License
--------
This software is licensed under the MPL 2.0 license. For more info check the LICENSE file.

Credits
---------

Tools used in rendering this package:

*  Cookiecutter_
*  `cookiecutter-djangopackage`_

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`cookiecutter-djangopackage`: https://github.com/pydanny/cookiecutter-djangopackage
