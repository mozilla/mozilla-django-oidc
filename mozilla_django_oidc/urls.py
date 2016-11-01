from django.conf.urls import url

from mozilla_django_oidc import views
from mozilla_django_oidc.utils import import_from_settings


OIDCCallbackClass = import_from_settings('OIDC_CALLBACK_CLASS',
                                         views.OIDCAuthenticationCallbackView)


urlpatterns = [
    url(r'^callback/$', OIDCCallbackClass.as_view(),
        name='oidc_authentication_callback'),
    url(r'^authenticate/$', views.OIDCAuthenticationRequestView.as_view(),
        name='oidc_authentication_init'),
]
