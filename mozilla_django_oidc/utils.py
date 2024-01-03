import logging
import time
import warnings
from hashlib import sha256
from urllib.parse import urlencode
from urllib.request import parse_http_list, parse_keqv_list

# Make it obvious that these aren't the usual base64 functions
import josepy.b64
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.urls import reverse
from django.utils.crypto import get_random_string

LOGGER = logging.getLogger(__name__)


def parse_www_authenticate_header(header):
    """
    Convert a WWW-Authentication header into a dict that can be used
    in a JSON response.
    """
    items = parse_http_list(header)
    return parse_keqv_list(items)


def import_from_settings(attr, *args):
    """
    Load an attribute from the django settings.

    :raises:
        ImproperlyConfigured
    """
    try:
        if args:
            return getattr(settings, attr, args[0])
        return getattr(settings, attr)
    except AttributeError:
        raise ImproperlyConfigured("Setting {0} not found".format(attr))


def absolutify(request, path):
    """Return the absolute URL of a path."""
    return request.build_absolute_uri(path)


def is_authenticated(user):
    """return True if the user is authenticated.
    This is necessary because in Django 1.10 the `user.is_authenticated`
    stopped being a method and is now a property.
    Actually `user.is_authenticated()` actually works, thanks to a backwards
    compat trick in Django. But in Django 2.0 it will cease to work
    as a callable method.
    """

    msg = "`is_authenticated()` is going to be removed in mozilla-django-oidc v 2.x"
    warnings.warn(msg, DeprecationWarning)
    return user.is_authenticated


def base64_url_encode(bytes_like_obj):
    """Return a URL-Safe, base64 encoded version of bytes_like_obj

    Implements base64urlencode as described in
    https://datatracker.ietf.org/doc/html/rfc7636#appendix-A
    """

    s = josepy.b64.b64encode(bytes_like_obj).decode("ascii")  # base64 encode
    # the josepy base64 encoder (strips '='s padding) automatically
    s = s.replace("+", "-")  # 62nd char of encoding
    s = s.replace("/", "_")  # 63rd char of encoding

    return s


def base64_url_decode(string_like_obj):
    """Return the bytes encoded in a URL-Safe, base64 encoded string
    Implements inverse of base64urlencode as described in
    https://datatracker.ietf.org/doc/html/rfc7636#appendix-A
    This function is not used by the OpenID client; it's just for testing PKCE related functions.
    """
    s = string_like_obj

    s = s.replace("_", "/")  # 63rd char of encoding
    s = s.replace("-", "+")  # 62nd char of encoding
    b = josepy.b64.b64decode(s)  # josepy base64 encoder (decodes without '='s padding)

    return b


def generate_code_challenge(code_verifier, method):
    """Return a code_challege, which proves knowledge of the code_verifier.
    The code challenge is generated according to method which must be one
    of the methods defined in https://datatracker.ietf.org/doc/html/rfc7636#section-4.2:
    - plain:
      code_challenge = code_verifier
    - S256:
      code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    """

    if method == "plain":
        return code_verifier

    elif method == "S256":
        return base64_url_encode(sha256(code_verifier.encode("ascii")).digest())

    else:
        raise ValueError("code challenge method must be 'plain' or 'S256'.")


def add_state_and_verifier_and_nonce_to_session(
    request, state, params, code_verifier=None
):
    """
    Stores the `state` and `nonce` parameters and an optional `code_verifier` (for PKCE) in a
    session dictionary which maps `state` -> {nonce, code_verifier}.  Each entry includes
    the time when it was added. The dictionary can contain multiple state -> {nonce, code_verifier}
    mappings to allow parallel logins with multiple browser sessions.
    To keep the session space to a reasonable size, the dictionary is kept at 50
    state -> {nonce, code_verifier} mappings maximum.
    """
    nonce = params.get("nonce")

    # OPs supporting PKCE will require `code_verifier` to be sent to the token
    # endpoint if `code_challenge` is sent to the authentication endpoint.
    # Make sure that `code_challenge` and `code_verifier` are both specified
    # or neither is.
    assert ("code_challenge" in params) == (code_verifier is not None)

    # Store Nonce with the State parameter in the session "oidc_states" dictionary.
    # The dictionary can store multiple State/Nonce combinations to allow parallel
    # authentication flows which would otherwise overwrite State/Nonce values!
    # The "oidc_states" dictionary uses the state as key and as value a dictionary with "nonce"
    # and "added_on". "added_on" contains the time when the state was added to the session.
    # With this value, the oldest element can be found and deleted from the session.
    if "oidc_states" not in request.session or not isinstance(
        request.session["oidc_states"], dict
    ):
        request.session["oidc_states"] = {}

    # Make sure that the State/Nonce dictionary in the session does not get too big.
    # If the number of State/Nonce combinations reaches a certain threshold, remove the oldest
    # state by finding out
    # which element has the oldest "add_on" time.
    limit = import_from_settings("OIDC_MAX_STATES", 50)
    if len(request.session["oidc_states"]) >= limit:
        LOGGER.info(
            'User has more than {} "oidc_states" in his session, '
            "deleting the oldest one!".format(limit)
        )
        oldest_state = None
        oldest_added_on = time.time()
        for item_state, item in request.session["oidc_states"].items():
            if item["added_on"] < oldest_added_on:
                oldest_state = item_state
                oldest_added_on = item["added_on"]
        if oldest_state:
            del request.session["oidc_states"][oldest_state]

    request.session["oidc_states"][state] = {
        "code_verifier": code_verifier,
        "nonce": nonce,
        "added_on": time.time(),
    }


class AuthorizationCodeRequestMixin:
    """
    Class that encapsulates the functionality required to make an authorization code request.
    """

    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

    def init_settings_for_authorization_code_request(self):
        self.OIDC_OP_AUTH_ENDPOINT = self.get_settings("OIDC_OP_AUTHORIZATION_ENDPOINT")
        self.OIDC_OP_AUTHORIZATION_ENDPOINT = self.OIDC_OP_AUTH_ENDPOINT
        self.OIDC_RP_CLIENT_ID = self.get_settings("OIDC_RP_CLIENT_ID")
        self.OIDC_STATE_SIZE = self.get_settings("OIDC_STATE_SIZE", 32)
        self.OIDC_AUTHENTICATION_CALLBACK_URL = self.get_settings(
            "OIDC_AUTHENTICATION_CALLBACK_URL",
            "oidc_authentication_callback",
        )
        self.OIDC_RP_SCOPES = self.get_settings("OIDC_RP_SCOPES", "openid email")
        self.OIDC_USE_NONCE = self.get_settings("OIDC_USE_NONCE", True)
        self.OIDC_NONCE_SIZE = self.get_settings("OIDC_NONCE_SIZE", 32)
        self.OIDC_USE_PKCE = self.get_settings("OIDC_USE_PKCE", False)
        self.OIDC_PKCE_CODE_VERIFIER_SIZE = self.get_settings(
            "OIDC_PKCE_CODE_VERIFIER_SIZE", 64
        )

        if not (43 <= self.OIDC_PKCE_CODE_VERIFIER_SIZE <= 128):
            # Check that OIDC_PKCE_CODE_VERIFIER_SIZE is between the min and max length
            # defined in https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
            raise ImproperlyConfigured(
                "OIDC_PKCE_CODE_VERIFIER_SIZE must be between 43 and 128"
            )

        self.OIDC_PKCE_CODE_CHALLENGE_METHOD = self.get_settings(
            "OIDC_PKCE_CODE_CHALLENGE_METHOD", "S256"
        )

        if self.OIDC_PKCE_CODE_CHALLENGE_METHOD not in ("plain", "S256"):
            raise ImproperlyConfigured(
                "OIDC_PKCE_CODE_CHALLENGE_METHOD must be 'plain' or 'S256'"
            )

    def get_extra_params(self, request):
        return self.get_settings("OIDC_AUTH_REQUEST_EXTRA_PARAMS", {})

    def get_url_for_authorization_code_request(self, request, **urlencode_kwargs):
        """
        Builds and returns the URL required for the authorization code request, and
        also adds the state, nonce, and code verifier (if using PKCE) to the session.
        """
        state = get_random_string(self.OIDC_STATE_SIZE)

        params = {
            "response_type": "code",
            "scope": self.OIDC_RP_SCOPES,
            "client_id": self.OIDC_RP_CLIENT_ID,
            "redirect_uri": absolutify(
                request, reverse(self.OIDC_AUTHENTICATION_CALLBACK_URL)
            ),
            "state": state,
        }

        params.update(self.get_extra_params(request))

        if self.OIDC_USE_NONCE:
            params.update(nonce=get_random_string(self.OIDC_NONCE_SIZE))

        if self.OIDC_USE_PKCE:
            code_verifier = get_random_string(self.OIDC_PKCE_CODE_VERIFIER_SIZE)
            params.update(
                code_challenge=generate_code_challenge(
                    code_verifier, self.OIDC_PKCE_CODE_CHALLENGE_METHOD
                ),
                code_challenge_method=self.OIDC_PKCE_CODE_CHALLENGE_METHOD,
            )
        else:
            code_verifier = None

        add_state_and_verifier_and_nonce_to_session(
            request, state, params, code_verifier
        )

        return f"{self.OIDC_OP_AUTHORIZATION_ENDPOINT}?{urlencode(params, **urlencode_kwargs)}"
