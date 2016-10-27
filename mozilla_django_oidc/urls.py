from django.conf.urls import url

from mozilla_django_oidc import views

urlpatterns = [
    url(r'^oidc/authentication_callback/$', views.OIDCAuthenticationCallbackView.as_view(),
        name='oidc_authentication_callback'),
    url(r'^oidc/authentication_init/$', views.OIDCAuthenticationRequestView.as_view(),
        name='oidc_authentication_init'),
]
