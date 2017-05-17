===================
mozilla-django-oidc
===================

.. image:: https://badge.fury.io/py/mozilla-django-oidc.png
    :target: https://badge.fury.io/py/mozilla-django-oidc

.. image:: https://travis-ci.org/mozilla/mozilla-django-oidc.png?branch=master
    :target: https://travis-ci.org/mozilla/mozilla-django-oidc

.. image:: https://img.shields.io/codecov/c/github/mozilla/mozilla-django-oidc.svg
   :target: https://codecov.io/gh/mozilla/mozilla-django-oidc

A lightweight authentication and access management library for integration with OpenID Connect enabled authentication services.


Documentation
-------------

The full documentation is at `<https://mozilla-django-oidc.readthedocs.io>`_.


Running Tests
-------------

Use ``tox`` to run as many different versions of Python you have. If you
don't have ``tox`` installed (and executable) already you can either
install it in your system Python or `<https://pypi.python.org/pypi/pipsi>`_.
Once installed, simply execute in the project root directory.

.. code-block:: shell

    $ tox

``tox`` will do the equivalent of installing virtual environments for every
combination mentioned in the ``tox.ini`` file. If your system, for example,
doesn't have ``python3.4`` those ``tox`` tests will be skipped.

For a faster test-rinse-repeat cycle you can run tests in a specific
environment with a specific version of Python and specific version of
Django of your choice. Here is such an example:


.. code-block:: shell

    $ virtualenv -p /path/to/bin/python3.5 venv
    $ source venv
    (venv) $ pip install Django==1.11.1
    (venv) $ pip install -r tests/requirements.txt
    (venv) $ DJANGO_SETTINGS_MODULE=tests.settings django-admin.py test

Measuring code coverage, continuing the steps above:

.. code-block:: shell

    (venv) $ pip install coverage
    (venv) $ DJANGO_SETTINGS_MODULE=tests.settings coverage run --source mozilla_django_oidc `which django-admin.py` test
    (venv) $ coverage report
    (venv) $ coverage html
    (venv) $ open htmlcov/index.html

Linting
-------

All code is checked with `<https://pypi.python.org/pypi/flake8>`_ in
continuous integration. To make sure your code still passes all style guides
install ``flake8`` and check:

.. code-block:: shell

    $ flake8 mozilla_django_oidc tests

.. note::

    When you run ``tox`` it also does a ``flake8`` run on the main package
    files and the tests.

You can also run linting with ``tox``:

.. code-block:: shell

    $ tox -e lint


License
-------

This software is licensed under the MPL 2.0 license. For more info check the LICENSE file.


Credits
-------

Tools used in rendering this package:

*  Cookiecutter_
*  `cookiecutter-djangopackage`_

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`cookiecutter-djangopackage`: https://github.com/pydanny/cookiecutter-djangopackage
