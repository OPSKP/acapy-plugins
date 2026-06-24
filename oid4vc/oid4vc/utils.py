"""Utility functions for OID4VCI plugin."""

import argparse
import hashlib
import hmac as _hmac
import json
from os import getenv
from typing import Dict, Optional

from acapy_agent.core.profile import Profile, ProfileSession
from acapy_agent.messaging.util import datetime_now
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.wallet.util import b58_to_bytes, bytes_to_b64, str_to_b64, unpad

from oid4vc.jwt import jwt_sign
from oid4vc.models.issuer_config import IssuerConfiguration
from oid4vc.models.supported_cred import SupportedCredential

EXPIRES_IN = 300


async def supported_cred_is_unique(identifier: str, profile: Profile):
    """Check whether a record exists with a given identifier."""

    async with profile.session() as session:
        records = await SupportedCredential.query(
            session, tag_filter={"identifier": identifier}
        )

    if len(records) > 0:
        return False
    return True


def get_wallet_id(profile: Profile) -> str:
    """Return the wallet ID for this profile, falling back to 'default-wallet'."""
    if profile.settings.get("multitenant.enabled"):
        return profile.settings.get("wallet.id") or "default-wallet"
    return "default-wallet"


async def get_first_auth_server(
    session: ProfileSession, profile: Profile
) -> Optional[dict]:
    """Return the first authorization_server entry from IssuerConfiguration.

    Falls back to OID4VCI_AUTH_SERVER_* environment variables when no
    database configuration exists for the current wallet.
    """
    wallet_id = get_wallet_id(profile)
    try:
        issuer_config = await IssuerConfiguration.retrieve_by_id(session, wallet_id)
        if issuer_config.authorization_servers:
            return issuer_config.authorization_servers[0]
    except StorageNotFoundError:
        pass

    # Fallback: bootstrap from OID4VCI_AUTH_SERVER_* environment variables
    auth_server_url = getenv("OID4VCI_AUTH_SERVER_URL")
    auth_server_type = getenv("OID4VCI_AUTH_SERVER_TYPE")
    auth_server_client_str = getenv("OID4VCI_AUTH_SERVER_CLIENT")
    if auth_server_url and auth_server_type and auth_server_client_str:
        client_info = json.loads(auth_server_client_str)
        return {
            "public_url": auth_server_url,
            "private_url": auth_server_url,
            "auth_type": auth_server_type,
            "client_credentials": {
                "client_id": client_info.get("client_id"),
                "client_secret": client_info.get("client_secret"),
                "username": client_info.get("username"),
                "password": client_info.get("password"),
            },
        }
    return None


def get_auth_server_url(auth_server: dict) -> Optional[str]:
    """Return the base URL for an auth server, preferring private_url over public_url."""
    return auth_server.get("private_url") or auth_server.get("public_url")


def get_tenant_subpath(profile: Profile, tenant_prefix: str = "/tenants") -> str:
    """Get the tenant path for the current wallet, if any."""

    wallet_id = (
        profile.settings.get("wallet.id")
        if profile.settings.get("multitenant.enabled")
        else None
    )
    tenant_subpath = f"{tenant_prefix}/{wallet_id}" if wallet_id else ""
    return tenant_subpath


def verkey_to_jwk(verkey: str) -> Dict:
    """Convert a base58 verkey (Ed25519) to a JWK dict."""

    key_bytes = b58_to_bytes(verkey)
    x = unpad(bytes_to_b64(key_bytes, urlsafe=True))
    jwk = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
    }
    return jwk


async def get_auth_header(
    profile: Profile, auth_server: dict, issuer: str, audience: str
) -> str:
    """Create an auth header for the given authorization server config dict.

    ``auth_server`` is an entry from ``IssuerConfiguration.authorization_servers``
    with keys ``auth_type``, ``client_credentials`` (and optionally ``public_url``,
    ``private_url``).
    """
    auth_type = auth_server.get("auth_type", "")
    client_creds = auth_server.get("client_credentials") or {}

    if not auth_type or not client_creds:
        raise ValueError("auth_server must specify 'auth_type' and 'client_credentials'.")

    if auth_type in ("client_secret_basic", "keycloak"):
        cred = f"{client_creds['client_id']}:{client_creds['client_secret']}"
        b64_cred = str_to_b64(cred)
        auth_header = f"Basic {b64_cred}"

    elif auth_type == "client_secret_jwt":
        utcnow = datetime_now()
        payload = {
            "iss": client_creds["client_id"],
            "sub": client_creds["client_id"],
            "aud": audience,
            "iat": int(utcnow.timestamp()),
            "exp": int(utcnow.timestamp()) + EXPIRES_IN,
        }

        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = unpad(bytes_to_b64(json.dumps(header).encode(), urlsafe=True))
        payload_b64 = unpad(bytes_to_b64(json.dumps(payload).encode(), urlsafe=True))
        signing_input = f"{header_b64}.{payload_b64}".encode()
        secret = client_creds["client_secret"].encode()
        sig = _hmac.new(secret, signing_input, hashlib.sha256).digest()
        sig_b64 = unpad(bytes_to_b64(sig, urlsafe=True))
        token = f"{header_b64}.{payload_b64}.{sig_b64}"
        auth_header = f"Bearer {token}"

    elif auth_type == "private_key_jwt":
        utcnow = datetime_now()
        payload = {
            "iss": f"{issuer}",
            "sub": f"{client_creds['client_id']}",
            "aud": f"{audience}",
            "iat": int(utcnow.timestamp()),
            "exp": int(utcnow.timestamp()) + EXPIRES_IN,
        }
        headers = {}
        token = await jwt_sign(
            profile,
            headers,
            payload,
            did=client_creds.get("did"),
            verification_method=client_creds.get("verification_method"),
        )
        auth_header = f"Bearer {token}"

    else:
        auth_header = ""

    return auth_header


if __name__ == "__main__":
    """Run as script to convert base58 verkey to JWK."""
    parser = argparse.ArgumentParser(description="Convert base58 verkey to JWK.")
    parser.add_argument("verkey", help="Base58-encoded Ed25519 public key")
    args = parser.parse_args()

    jwk = verkey_to_jwk(args.verkey)
    jwks = {"keys": [jwk]}
    print(json.dumps(jwks))
