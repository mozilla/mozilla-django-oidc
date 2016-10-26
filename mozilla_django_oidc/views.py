from django.contrib import auth
from django.http import HttpResponseRedirect
from django.views.generic import View

from mozilla_django_oidc.utils import import_from_settings


class OIDCAuthorizationCallbackView(View):
    """OIDC client authentication callback HTTP endpoint"""

    http_method_names = ['post']

    @property
    def failure_url(self):
        return import_from_settings('LOGIN_REDIRECT_URL_FAILURE', '/')

    @property
    def success_url(self):
        return import_from_settings('LOGIN_REDIRECT_URL', '/')

    def login_failure(self):
        return HttpResponseRedirect(self.failure_url)

    def login_success(self):
        auth.login(self.request, self.user)
        return HttpResponseRedirect(self.success_url)

    def post(self, request):
        """Callback handler for OIDC authorization code flow"""

        if 'code' in request.POST and 'state' in request.POST:
            kwargs = {
                'code': request.POST['code'],
                'state': request.POST['state']
            }
            self.user = auth.authenticate(**kwargs)

            if self.user and self.user.is_active:
                return self.login_success()
        return self.login_failure()
