from django.test.client import Client


class OIDCClient(Client):
    oidc_id_token = 'some_oidc_token'

    def __init__(self, enforce_csrf_checks=False, **defaults):
        super(OIDCClient, self).__init__(enforce_csrf_checks=enforce_csrf_checks, **defaults)
        session = self.session
        session['oidc_id_token'] = self.oidc_id_token
        session.save()
