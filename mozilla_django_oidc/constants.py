from enum import Enum


class OPMetadataKey(Enum):
    """Keys found in openid provider's metadata json"""

    AUTHORIZATION_ENDPOINT = 'authorization_endpoint'
    TOKEN_ENDPOINT = 'token_endpoint'
    USER_INFO_ENDPOINT = 'userinfo_endpoint'
    JWKS_ENDPOINT = 'jwks_uri'


class OIDCCacheKey(Enum):
    """Keys for cache used in OIDC."""
    OP_METADATA = 'op_metadata'
