from django.urls import path, include

urlpatterns = [path("namespace/", include(("mozilla_django_oidc.urls", "namespace")))]
