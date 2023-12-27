import time
from urllib.parse import urlencode

from django.contrib import auth
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponseNotAllowed, HttpResponseRedirect
from django.shortcuts import resolve_url
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.module_loading import import_string
from django.views.generic import View

from mozilla_django_oidc.utils import (
    absolutify,
    add_state_and_verifier_and_nonce_to_session,
    generate_code_challenge,
    import_from_settings,
)


class OIDCAuthenticationCallbackView(View):
    """OIDC client authentication callback HTTP endpoint"""

    http_method_names = ["get"]

    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

    @property
    def failure_url(self):
        return self.get_settings("LOGIN_REDIRECT_URL_FAILURE", "/")

    @property
    def success_url(self):
        # Pull the next url from the session or settings--we don't need to
        # sanitize here because it should already have been sanitized.
        next_url = self.request.session.get("oidc_login_next", None)
        return next_url or resolve_url(self.get_settings("LOGIN_REDIRECT_URL", "/"))

    def login_failure(self):
        return HttpResponseRedirect(self.failure_url)

    def login_success(self):
        # If the user hasn't changed (because this is a session refresh instead of a
        # normal login), don't call login. This prevents invaliding the user's current CSRF token
        request_user = getattr(self.request, "user", None)
        if (
            not request_user
            or not request_user.is_authenticated
            or request_user != self.user
        ):
            auth.login(self.request, self.user)

        # Figure out when this id_token will expire. This is ignored unless you're
        # using the SessionRefresh middleware.
        expiration_interval = self.get_settings(
            "OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS", 60 * 15
        )
        self.request.session["oidc_id_token_expiration"] = (
            time.time() + expiration_interval
        )

        return HttpResponseRedirect(self.success_url)

    def get(self, request):
        """Callback handler for OIDC authorization code flow"""

        if request.GET.get("error"):
            # Ouch! Something important failed.

            # Delete the state entry also for failed authentication attempts
            # to prevent replay attacks.
            if (
                "state" in request.GET
                and "oidc_states" in request.session
                and request.GET["state"] in request.session["oidc_states"]
            ):
                del request.session["oidc_states"][request.GET["state"]]
                request.session.save()

            # Make sure the user doesn't get to continue to be logged in
            # otherwise the refresh middleware will force the user to
            # redirect to authorize again if the session refresh has
            # expired.
            if request.user.is_authenticated:
                auth.logout(request)
            assert not request.user.is_authenticated
        elif "code" in request.GET and "state" in request.GET:
            # Check instead of "oidc_state" check if the "oidc_states" session key exists!
            if "oidc_states" not in request.session:
                return self.login_failure()

            # State, Nonce and PKCE Code Verifier are stored in the session "oidc_states"
            # dictionary.
            # State is the key, the value is a dictionary with the Nonce in the "nonce" field, and
            # Code Verifier or None in the "code_verifier" field.
            state = request.GET.get("state")
            if state not in request.session["oidc_states"]:
                msg = "OIDC callback state not found in session `oidc_states`!"
                raise SuspiciousOperation(msg)

            # Get the nonce and optional code verifier from the dictionary for further processing
            # and delete the entry to prevent replay attacks.
            code_verifier = request.session["oidc_states"][state].get("code_verifier")
            nonce = request.session["oidc_states"][state]["nonce"]
            del request.session["oidc_states"][state]

            # Authenticating is slow, so save the updated oidc_states.
            request.session.save()
            # Reset the session. This forces the session to get reloaded from the database after
            # fetching the token from the OpenID connect provider.
            # Without this step we would overwrite items that are being added/removed from the
            # session in parallel browser tabs.
            request.session = request.session.__class__(request.session.session_key)

            kwargs = {
                "request": request,
                "nonce": nonce,
                "code_verifier": code_verifier,
            }

            self.user = auth.authenticate(**kwargs)

            if self.user and self.user.is_active:
                return self.login_success()
        return self.login_failure()


def get_next_url(request, redirect_field_name):
    """Retrieves next url from request

    Note: This verifies that the url is safe before returning it. If the url
    is not safe, this returns None.

    :arg HttpRequest request: the http request
    :arg str redirect_field_name: the name of the field holding the next url

    :returns: safe url or None

    """
    next_url = request.GET.get(redirect_field_name)
    if next_url:
        kwargs = {
            "url": next_url,
            "require_https": import_from_settings(
                "OIDC_REDIRECT_REQUIRE_HTTPS", request.is_secure()
            ),
        }

        hosts = list(import_from_settings("OIDC_REDIRECT_ALLOWED_HOSTS", []))
        hosts.append(request.get_host())
        kwargs["allowed_hosts"] = hosts

        is_safe = url_has_allowed_host_and_scheme(**kwargs)
        if is_safe:
            return next_url
    return None


class OIDCAuthenticationRequestView(View):
    """OIDC client authentication HTTP endpoint"""

    http_method_names = ["get"]

    def __init__(self, *args, **kwargs):
        super(OIDCAuthenticationRequestView, self).__init__(*args, **kwargs)

        self.OIDC_OP_AUTH_ENDPOINT = self.get_settings("OIDC_OP_AUTHORIZATION_ENDPOINT")
        self.OIDC_RP_CLIENT_ID = self.get_settings("OIDC_RP_CLIENT_ID")

    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

    def get(self, request):
        """OIDC client authentication initialization HTTP endpoint"""
        state = get_random_string(self.get_settings("OIDC_STATE_SIZE", 32))
        redirect_field_name = self.get_settings("OIDC_REDIRECT_FIELD_NAME", "next")
        reverse_url = self.get_settings(
            "OIDC_AUTHENTICATION_CALLBACK_URL", "oidc_authentication_callback"
        )

        params = {
            "response_type": "code",
            "scope": self.get_settings("OIDC_RP_SCOPES", "openid email"),
            "client_id": self.OIDC_RP_CLIENT_ID,
            "redirect_uri": absolutify(request, reverse(reverse_url)),
            "state": state,
        }

        params.update(self.get_extra_params(request))

        if self.get_settings("OIDC_USE_NONCE", True):
            nonce = get_random_string(self.get_settings("OIDC_NONCE_SIZE", 32))
            params.update({"nonce": nonce})

        if self.get_settings("OIDC_USE_PKCE", False):
            code_verifier_length = self.get_settings("OIDC_PKCE_CODE_VERIFIER_SIZE", 64)
            # Check that code_verifier_length is between the min and max length
            # defined in https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
            if not (43 <= code_verifier_length <= 128):
                raise ValueError("code_verifier_length must be between 43 and 128")

            # Generate code_verifier and code_challenge pair
            code_verifier = get_random_string(code_verifier_length)
            code_challenge_method = self.get_settings(
                "OIDC_PKCE_CODE_CHALLENGE_METHOD", "S256"
            )
            code_challenge = generate_code_challenge(
                code_verifier, code_challenge_method
            )

            # Append code_challenge to authentication request parameters
            params.update(
                {
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                }
            )

        else:
            code_verifier = None

        add_state_and_verifier_and_nonce_to_session(
            request, state, params, code_verifier
        )

        request.session["oidc_login_next"] = get_next_url(request, redirect_field_name)

        query = urlencode(params)
        redirect_url = "{url}?{query}".format(
            url=self.OIDC_OP_AUTH_ENDPOINT, query=query
        )
        return HttpResponseRedirect(redirect_url)

    def get_extra_params(self, request):
        return self.get_settings("OIDC_AUTH_REQUEST_EXTRA_PARAMS", {})


class OIDCLogoutView(View):
    """Logout helper view"""

    http_method_names = ["get", "post"]

    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

    @property
    def redirect_url(self):
        """Return the logout url defined in settings."""
        return self.get_settings("LOGOUT_REDIRECT_URL", "/")

    def post(self, request):
        """Log out the user."""
        logout_url = self.redirect_url

        if request.user.is_authenticated:
            # Check if a method exists to build the URL to log out the user
            # from the OP.
            logout_from_op = self.get_settings("OIDC_OP_LOGOUT_URL_METHOD", "")
            if logout_from_op:
                logout_url = import_string(logout_from_op)(request)

            # Log out the Django user if they were logged in.
            auth.logout(request)

        return HttpResponseRedirect(logout_url)

    def get(self, request):
        """Log out the user."""
        if self.get_settings("ALLOW_LOGOUT_GET_METHOD", False):
            return self.post(request)
        return HttpResponseNotAllowed(["POST"])
