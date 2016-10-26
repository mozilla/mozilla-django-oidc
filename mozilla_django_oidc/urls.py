from django.conf.urls import url

from mozilla_django_oidc import views

urlpatterns = [
    url(r'^oidc/authorization_callback/$', views.OIDCAuthorizationCallbackView.as_view(),
        name='oidc_authorization_callback'),
]
