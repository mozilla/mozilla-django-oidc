from django.conf.urls import url

from mozilla_django_oidc import views

urlpatterns = [
    url(r'^callback/$', views.OIDCAuthenticationCallbackView.as_view(),
        name='oidc_authentication_callback'),
    url(r'^authenticate/$', views.OIDCAuthenticationRequestView.as_view(),
        name='oidc_authentication_init'),
]
