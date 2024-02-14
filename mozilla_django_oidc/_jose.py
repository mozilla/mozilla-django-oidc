"""
Helpers for dealing with Javascript Object Signing and Encryption (JOSE) in an OpenID
Connect context.
"""
import json
from typing import Dict, Any, TypeAlias, Union

from django.core.exceptions import SuspiciousOperation
from django.utils.encoding import smart_bytes

from josepy.jwk import JWK
from josepy.jws import JWS

# values could be narrowed down to relevant JSON types.
Payload: TypeAlias = Dict[str, Any]


def verify_jws_and_decode(
    token: bytes,
    key,
    signing_algorithm: str = "",
    decode_json: bool = False,  # for backwards compatibility reasons
) -> Union[Payload, bytes]:
    """
    Cryptographically verify the passed in token and return the decoded payload.

    Verification is done with utilities from the josepy library.

    :arg token: the raw binary content of the JWT/token.
    :arg key: the key to verify the signature with. This may be a key obtained from
      the OIDC_OP_JWKS_ENDPOINT or a shared key as a string (XXX CONFIRM THIS!)
    :arg signing_algorithm: If provided, the token must employ this exact signing
      algorithm. Values must be valid names from algorithms in :mod:`josepy.jwa`.
    :arg decode_json: If true, the payload will be json-decoded and return a Python
      object rather than a bytestring.
    :return: the extracted payload object, deserialized from JSON.
    :raises SuspiciousOperation: if the token verification fails.
    """
    jws = JWS.from_compact(token)

    # validate the signing algorithm
    if (alg := jws.signature.combined.alg) is None:
        msg = "No alg value found in header"
        raise SuspiciousOperation(msg)

    if signing_algorithm and signing_algorithm != alg.name:
        msg = (
            "The provider algorithm {!r} does not match the client's "
            "expected signing algorithm.".format(alg)
        )
        raise SuspiciousOperation(msg)

    # one of the most common implementation weaknesses -> attacker can supply 'none'
    # algorithm
    # XXX: check if this is okay, technically users can now set
    # settings.OIDC_RP_SIGN_ALGO = "none" and things should work?
    if alg.name == "none":
        raise SuspiciousOperation("'none' for alg value is not allowed")

    # process the key parameter which was/may have been loaded from keys endpoint
    if isinstance(key, str):
        # Use smart_bytes here since the key string comes from settings.
        jwk = JWK.load(smart_bytes(key))
    else:
        # The key is a json returned from the IDP JWKS endpoint.
        jwk = JWK.from_json(key)
        # address some missing upstream Self type declarations
        assert isinstance(jwk, JWK)

    if not jws.verify(jwk):
        msg = "JWS token verification failed."
        raise SuspiciousOperation(msg)

    # return the decoded JSON or the raw bytestring payload
    payload = jws.payload
    if not decode_json:
        return payload
    else:
        return json.loads(payload.decode("utf-8"))
