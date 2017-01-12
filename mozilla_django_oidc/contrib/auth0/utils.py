import requests
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

from mozilla_django_oidc.utils import import_from_settings


def refresh_id_token(id_token):
    """Renews the id_token from the delegation endpoint in Auth0."""
    delegation_url = 'https://{0}/delegation'.format(import_from_settings('OIDC_OP_DOMAIN'))
    data = {
        'client_id': import_from_settings('OIDC_RP_CLIENT_ID'),
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'id_token': id_token,
        'api_type': 'app'
    }

    response = requests.post(delegation_url, data=data)

    if response.status_code == requests.codes.ok:
        return response.json().get('id_token')
    return None


def logout_url():
    """Log out the user from Auth0."""
    url = 'https//' + import_from_settings('OIDC_OP_DOMAIN') + '/v2/logout'
    url += '?' + urlencode({
        'returnTo': import_from_settings('LOGOUT_REDIRECT_URL', '/'),
        'client_id': import_from_settings('OIDC_RP_CLIENT_ID')
    })
    return url
