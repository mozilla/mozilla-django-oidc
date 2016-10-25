from django.conf import settings
from django.core.exceptions import ImproperlyConfigured


def import_from_settings(attr, default_val=None):
    """
    Load an attribute from the django settings.

    :raises:
        ImproperlyConfigured
    """
    try:
        if default_val:
            return getattr(settings, attr, default_val)
        return getattr(settings, attr)
    except AttributeError as e:
        raise ImproperlyConfigured('Setting {0} not found'.format(attr))
