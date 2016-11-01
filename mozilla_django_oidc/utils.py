try:
    from urlparse import urljoin
except ImportError:
    from urllib.parse import urljoin

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def import_from_settings(attr, *args):
    """
    Load an attribute from the django settings.

    :raises:
        ImproperlyConfigured
    """
    try:
        if args:
            return getattr(settings, attr, args[0])
        return getattr(settings, attr)
    except AttributeError:
        raise ImproperlyConfigured('Setting {0} not found'.format(attr))


def absolutify(path):
    """Return the absolute URL of url_path."""

    site_url = import_from_settings('SITE_URL')
    return urljoin(site_url, path)
