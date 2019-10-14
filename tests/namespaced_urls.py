from django.conf.urls import url, include

urlpatterns = [url(r'^namespace/', include(('mozilla_django_oidc.urls', 'namespace')))]
