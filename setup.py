#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from mozilla_django_oidc import __version__ as VERSION

if sys.argv[-1] == "publish":
    try:
        import wheel

        print("Wheel version: ", wheel.__version__)
    except ImportError:
        print('Wheel library missing. Please run "pip install wheel"')
        sys.exit()
    os.system("python setup.py sdist upload")
    os.system("python setup.py bdist_wheel upload")
    sys.exit()

if sys.argv[-1] == "tag":
    print("Tagging the version on git:")
    os.system("git tag -a %s -m 'version %s'" % (VERSION, VERSION))
    os.system("git push --tags")
    sys.exit()

readme = open("README.rst").read()
history = open("HISTORY.rst").read().replace(".. :changelog:", "")

install_requirements = [
    "Django >= 3.2",
    "josepy",
    "requests",
    "cryptography",
]

setup(
    name="mozilla-django-oidc",
    version=VERSION,
    description="""A lightweight authentication and access management library for integration with OpenID Connect enabled authentication services.""",  # noqa
    long_description=readme + "\n\n" + history,
    author="Tasos Katsoulas, John Giannelos",
    author_email="akatsoulas@mozilla.com, jgiannelos@mozilla.com",
    url="https://github.com/mozilla/mozilla-django-oidc",
    packages=["mozilla_django_oidc"],
    include_package_data=True,
    install_requires=install_requirements,
    license="MPL 2.0",
    zip_safe=False,
    keywords="mozilla-django-oidc",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Framework :: Django",
        "Framework :: Django :: 3.2",
        "Framework :: Django :: 4.2",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Intended Audience :: Developers",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
