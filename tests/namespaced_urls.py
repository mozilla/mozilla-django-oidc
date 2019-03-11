import django
from django.conf.urls import url, include


if django.VERSION < (1, 8, 99):
    urlpatterns = [url(r'^namespace/', include('mozilla_django_oidc.urls', namespace='namespace'))]
else:
    urlpatterns = [url(r'^namespace/', include(('mozilla_django_oidc.urls', 'namespace')))]
