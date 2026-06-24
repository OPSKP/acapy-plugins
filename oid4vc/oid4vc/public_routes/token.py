"""Token endpoint for OID4VCI."""

import base64 as _base64
import datetime
import hashlib as _hashlib
import hmac
import json
import time
from datetime import UTC
from typing import Any, Dict
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature as _InvalidSignature
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric import padding as _padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers as _RSAPublicNumbers

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.base import WalletError
from acapy_agent.wallet.error import WalletNotFoundError
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.wallet.util import b64_to_bytes
from aiohttp import web
from aiohttp_apispec import docs, form_schema
from aries_askar import Key
from marshmallow import fields, pre_load

from oid4vc.did_utils import retrieve_or_create_did_jwk
from oid4vc.jwt import (
    JWTVerifyResult,
    jwt_sign,
    jwt_verify,
    key_from_x5c,
    key_material_for_kid,
)

from ..app_resources import AppResources
from ..config import Config
from ..models.exchange import OID4VCIExchangeRecord
from ..models.nonce import Nonce
from ..pop_result import PopResult
from ..utils import (
    get_auth_header,
    get_auth_server_url,
    get_first_auth_server,
    get_tenant_subpath,
)
from .constants import (
    EXPIRES_IN,
    LOGGER,
    NONCE_BYTES,
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
)
from .nonce import create_nonce


class GetTokenSchema(OpenAPISchema):
    """Schema for the token endpoint.

    Accept both 'pre-authorized_code' (OID4VCI v1.0) and legacy
    'pre_authorized_code' (underscore) for compatibility by normalizing input.
    """

    grant_type = fields.Str(required=True, metadata={"description": "", "example": ""})

    pre_authorized_code = fields.Str(
        data_key="pre-authorized_code",
        required=True,
        metadata={"description": "", "example": ""},
    )
    user_pin = fields.Str(required=False)

    @pre_load
    def normalize_fields(self, data, **_kwargs):
        """Normalize legacy field names to OID4VCI v1.0 keys.

        Accept 'pre_authorized_code' by mapping it to 'pre-authorized_code'.
        """
        # webargs may pass a MultiDictProxy; make a writable copy first
        try:
            mutable = dict(data)
        except (TypeError, ValueError):
            mutable = data
        # Map legacy underscore field to the hyphenated v1.0 key if needed
        if "pre_authorized_code" in mutable and "pre-authorized_code" not in mutable:
            mutable["pre-authorized_code"] = mutable.get("pre_authorized_code")
        return mutable


@docs(tags=["oid4vci"], summary="Get credential issuance token")
@form_schema(GetTokenSchema())
async def token(request: web.Request):
    """Token endpoint to exchange pre-authorized codes for access tokens.

    OID4VCI v1.0: This step MUST NOT require DID or verification method.
    """
    context: AdminRequestContext = request["context"]
    async with context.profile.session() as session:
        auth_server = await get_first_auth_server(session, context.profile)
    if auth_server:
        # The wallet should never reach this endpoint when an external auth server
        # is configured — it should obtain a token directly from the auth server's
        # token_endpoint advertised in the AS well-known metadata.  Return an
        # explicit error rather than silently proxying.
        raise web.HTTPBadRequest(
            reason="Token endpoint not available: use the authorization server"
        )
    form = await request.post()
    LOGGER.debug("Token request form: %s", dict(form))

    if (form.get("grant_type")) != PRE_AUTHORIZED_CODE_GRANT_TYPE:
        return web.json_response(
            {
                "error": "unsupported_grant_type",
                "error_description": "grant_type not supported",
            },
            status=400,
        )

    # Accept both hyphenated and underscored keys
    pre_authorized_code = form.get("pre-authorized_code") or form.get(
        "pre_authorized_code"
    )
    if not pre_authorized_code or not isinstance(pre_authorized_code, str):
        return web.json_response(
            {
                "error": "invalid_request",
                "error_description": "pre-authorized_code is missing or invalid",
            },
            status=400,
        )

    # Accept both legacy user_pin and OID4VCI 1.0 final tx_code in token requests.
    user_pin = form.get("tx_code") or form.get("user_pin")
    try:
        async with context.profile.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_code(
                session, pre_authorized_code
            )
    except (StorageError, BaseModelError, StorageNotFoundError) as err:
        return web.json_response(
            {"error": "invalid_grant", "error_description": err.roll_up}, status=400
        )

    if record.pin is not None:
        if user_pin is None:
            return web.json_response(
                {
                    "error": "invalid_request",
                    "error_description": "user_pin is required",
                },
                status=400,
            )
        if not hmac.compare_digest(user_pin, record.pin):
            return web.json_response(
                {"error": "invalid_grant", "error_description": "pin is invalid"},
                status=400,
            )

    # Check if pre-authorized code has already been used
    if record.token is not None:
        return web.json_response(
            {
                "error": "invalid_grant",
                "error_description": "pre-authorized code has already been used",
            },
            status=400,
        )

    payload = {
        "sub": record.refresh_id,
        "exp": int(time.time()) + EXPIRES_IN,
    }

    # v1 compliance: do not require DID/verification method at token step.
    # Sign with a default did:jwk under this wallet to produce a JWT access token.
    async with context.profile.session() as session:
        try:
            jwk_info = await retrieve_or_create_did_jwk(session)
            vm = f"{jwk_info.did}#0"
            token_jwt = await jwt_sign(
                context.profile,
                headers={"kid": vm, "typ": "JWT"},
                payload=payload,
                verification_method=vm,
            )
        except (WalletNotFoundError, WalletError, ValueError) as err:
            return web.json_response(
                {
                    "error": "server_error",
                    "error_description": f"Unable to sign access token: {str(err)}",
                },
                status=500,
            )

        record.token = token_jwt
        await record.save(
            session,
            reason="Created new token",
        )

    # Create a nonce for the wallet to use in its credential proof.
    # The /nonce endpoint also serves nonces (OID4VCI 1.0 §8); both are valid.
    c_nonce_record = await create_nonce(context.profile, NONCE_BYTES, EXPIRES_IN)

    return web.json_response(
        {
            "access_token": record.token,
            "token_type": "Bearer",
            "expires_in": EXPIRES_IN,
            "c_nonce": c_nonce_record.nonce_value,
            "c_nonce_expires_in": EXPIRES_IN,
        }
    )


def _b64url_to_int(b64url: str) -> int:
    padded = b64url + "=" * (4 - len(b64url) % 4)
    return int.from_bytes(_base64.urlsafe_b64decode(padded), "big")


def _verify_sig_with_jwk(
    signing_input: bytes,
    sig: bytes,
    jwk: dict,
    alg: str,
) -> None:
    """Verify a JWT or DPoP proof signature using a JWK.

    Raises web.HTTPUnauthorized on failure.
    """
    kty = jwk.get("kty", "")
    try:
        if kty == "RSA":
            pub_key = _RSAPublicNumbers(
                e=_b64url_to_int(jwk["e"]),
                n=_b64url_to_int(jwk["n"]),
            ).public_key()
            h = {
                "RS256": _hashes.SHA256(), "RS384": _hashes.SHA384(), "RS512": _hashes.SHA512(),
                "PS256": _hashes.SHA256(), "PS384": _hashes.SHA384(), "PS512": _hashes.SHA512(),
            }.get(alg, _hashes.SHA256())
            pad = (
                _padding.PSS(mgf=_padding.MGF1(h), salt_length=_padding.PSS.MAX_LENGTH)
                if alg.startswith("PS") else _padding.PKCS1v15()
            )
            pub_key.verify(sig, signing_input, pad, h)

        elif kty == "EC":
            curve = {
                "P-256": _ec.SECP256R1(), "P-384": _ec.SECP384R1(), "P-521": _ec.SECP521R1(),
            }.get(jwk.get("crv", "P-256"), _ec.SECP256R1())
            pub_key = _ec.EllipticCurvePublicKey.from_encoded_point(
                curve,
                b"\x04"
                + _base64.urlsafe_b64decode(jwk["x"] + "==")
                + _base64.urlsafe_b64decode(jwk["y"] + "=="),
            )
            h = {"ES256": _hashes.SHA256(), "ES384": _hashes.SHA384(), "ES512": _hashes.SHA512()}.get(
                alg, _hashes.SHA256()
            )
            pub_key.verify(sig, signing_input, _ec.ECDSA(h))

        elif kty == "OKP":
            askar_key = Key.from_jwk(json.dumps(jwk))
            if not askar_key.verify_signature(signing_input, sig, sig_type=alg):
                raise _InvalidSignature

        else:
            raise web.HTTPUnauthorized(reason=f"Unsupported key type: {kty}")

    except _InvalidSignature:
        raise web.HTTPUnauthorized(reason="Invalid signature")
    except web.HTTPUnauthorized:
        raise
    except Exception as exc:
        raise web.HTTPUnauthorized(reason=f"Signature verification failed: {exc}")


def _jwk_thumbprint(jwk: dict) -> str:
    """Compute JWK thumbprint per RFC 7638 (SHA-256, base64url)."""
    kty = jwk.get("kty")
    members: list[str]
    if kty == "EC":
        members = ["crv", "kty", "x", "y"]
    elif kty == "RSA":
        members = ["e", "kty", "n"]
    elif kty == "OKP":
        members = ["crv", "kty", "x"]
    else:
        raise ValueError(f"Unsupported kty for thumbprint: {kty}")
    canonical = json.dumps({k: jwk[k] for k in sorted(members)}, separators=(",", ":"))
    digest = _hashlib.sha256(canonical.encode()).digest()
    return _base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _validate_dpop(
    proof_jwt: str,
    access_token: str,
    request_method: str,
    request_uri: str,
    max_age: int = 300,
) -> None:
    """Validate a DPoP proof JWT per RFC 9449 §4.3.

    Checks: typ, alg, htm, htu, iat freshness, ath (access token hash),
    and proof signature. jti replay protection is not implemented here.
    """
    parts = proof_jwt.split(".")
    if len(parts) != 3:
        raise web.HTTPUnauthorized(reason="Malformed DPoP proof")
    h_b64, p_b64, s_b64 = parts
    try:
        proof_header = b64_to_dict(h_b64)
        proof_payload = b64_to_dict(p_b64)
    except Exception:
        raise web.HTTPUnauthorized(reason="Invalid DPoP proof JWT encoding")

    if proof_header.get("typ") != "dpop+jwt":
        raise web.HTTPUnauthorized(reason="DPoP proof typ must be 'dpop+jwt'")
    alg = proof_header.get("alg", "")
    if not alg or alg == "none":
        raise web.HTTPUnauthorized(reason="DPoP proof missing valid alg")
    jwk = proof_header.get("jwk")
    if not jwk:
        raise web.HTTPUnauthorized(reason="DPoP proof header missing jwk")

    if proof_payload.get("htm", "").upper() != request_method.upper():
        raise web.HTTPUnauthorized(
            reason=f"DPoP htm mismatch: got {proof_payload.get('htm')!r}, expected {request_method!r}"
        )

    def _bare(uri: str) -> str:
        p = urlparse(uri)
        return f"{p.scheme}://{p.netloc}{p.path}"

    if _bare(proof_payload.get("htu", "")) != _bare(request_uri):
        raise web.HTTPUnauthorized(
            reason=f"DPoP htu mismatch: got {proof_payload.get('htu')!r}, expected {request_uri!r}"
        )

    if abs(time.time() - proof_payload.get("iat", 0)) > max_age:
        raise web.HTTPUnauthorized(reason="DPoP proof iat outside acceptable window")

    # ath: SHA-256 of the ASCII access token per RFC 9449 §4.2
    ath = proof_payload.get("ath")
    if ath:
        expected_ath = (
            _base64.urlsafe_b64encode(
                _hashlib.sha256(access_token.encode()).digest()
            )
            .rstrip(b"=")
            .decode()
        )
        if ath != expected_ath:
            raise web.HTTPUnauthorized(reason="DPoP ath does not match access token hash")

    _verify_sig_with_jwk(
        f"{h_b64}.{p_b64}".encode(),
        b64_to_bytes(s_b64, urlsafe=True),
        jwk,
        alg,
    )


async def _verify_keycloak_jwt(token: str, auth_server: dict) -> JWTVerifyResult:
    """Validate a Keycloak-issued JWT locally using Keycloak's JWKS endpoint.

    Keycloak OID4VCI DPoP tokens have aud set to Keycloak's own credential
    endpoint, making introspection by acapy-issuer fail the audience check.
    Local JWKS validation avoids that restriction.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise web.HTTPUnauthorized()
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = b64_to_dict(header_b64)
        payload = b64_to_dict(payload_b64)
    except Exception:
        raise web.HTTPUnauthorized()

    kid = header.get("kid")
    alg = header.get("alg", "")

    private_url = get_auth_server_url(auth_server)
    jwks_resp = await AppResources.get_http_client().get(
        f"{private_url}/protocol/openid-connect/certs"
    )
    if jwks_resp.status != 200:
        raise web.HTTPUnauthorized(reason="Could not fetch Keycloak JWKS")
    jwks = await jwks_resp.json()

    key_data = next(
        (k for k in jwks.get("keys", []) if k.get("kid") == kid),
        None,
    )
    if not key_data:
        raise web.HTTPUnauthorized(reason="Signing key not found in JWKS")

    _verify_sig_with_jwk(
        f"{header_b64}.{payload_b64}".encode(),
        b64_to_bytes(sig_b64, urlsafe=True),
        key_data,
        alg,
    )

    if payload.get("exp", 0) < time.time():
        raise web.HTTPUnauthorized(reason="Token expired")

    return JWTVerifyResult(headers=header, payload=payload, verified=True)


async def check_token(
    context: AdminRequestContext,
    bearer: str | None = None,
    dpop_proof: str | None = None,
    request_method: str = "POST",
    request_uri: str = "",
) -> JWTVerifyResult:
    """Validate the OID4VCI access token per RFC 9449.

    Accepts both ``Bearer`` and ``DPoP`` Authorization schemes.  When the
    scheme is ``DPoP``, the DPoP proof JWT is validated (htm, htu, iat,
    ath, signature) and the token's ``cnf.jkt`` binding is verified against
    the proof's embedded public key.
    """
    if not bearer:
        raise web.HTTPUnauthorized()
    try:
        scheme, cred = bearer.split(" ", 1)
    except ValueError:
        raise web.HTTPUnauthorized() from None
    if scheme.lower() not in ("bearer", "dpop"):
        raise web.HTTPUnauthorized()

    config = Config.from_settings(context.settings)
    profile = context.profile

    async with profile.session() as session:
        auth_server = await get_first_auth_server(session, profile)

    if auth_server:
        auth_type = auth_server.get("auth_type", "")
        private_url = get_auth_server_url(auth_server)
        if auth_type == "keycloak":
            result = await _verify_keycloak_jwt(cred, auth_server)
        else:
            subpath = get_tenant_subpath(profile, tenant_prefix="/tenant")
            issuer_server_url = f"{config.endpoint}{subpath}"
            introspect_endpoint = f"{private_url}/introspect"
            auth_header = await get_auth_header(
                profile, auth_server, issuer_server_url, introspect_endpoint
            )
            resp = await AppResources.get_http_client().post(
                introspect_endpoint,
                data={"token": cred},
                headers={"Authorization": auth_header},
            )
            introspect = await resp.json()
            if not introspect.get("active"):
                raise web.HTTPUnauthorized(reason="invalid_token")
            result = JWTVerifyResult(headers={}, payload=introspect, verified=True)
    else:
        result = await jwt_verify(context.profile, cred)
        if not result.verified:
            raise web.HTTPUnauthorized(
                text='{"error": "invalid_token", '
                '"error_description": "Token verification failed"}',
                headers={"Content-Type": "application/json"},
            )
        if result.payload["exp"] < datetime.datetime.now(UTC).timestamp():
            raise web.HTTPUnauthorized(
                text='{"error": "invalid_token", "error_description": "Token expired"}',
                headers={"Content-Type": "application/json"},
            )

    # DPoP binding validation per RFC 9449 §7
    if scheme.lower() == "dpop":
        if not dpop_proof:
            raise web.HTTPUnauthorized(reason="DPoP scheme requires DPoP proof header")
        _validate_dpop(dpop_proof, cred, request_method, request_uri)
        cnf = result.payload.get("cnf", {})
        jkt = cnf.get("jkt")
        if jkt:
            try:
                proof_header = b64_to_dict(dpop_proof.split(".")[0])
                jwk = proof_header.get("jwk", {})
                if _jwk_thumbprint(jwk) != jkt:
                    raise web.HTTPUnauthorized(reason="DPoP cnf.jkt does not match proof key")
            except web.HTTPUnauthorized:
                raise
            except Exception as exc:
                raise web.HTTPUnauthorized(reason=f"DPoP cnf.jkt check failed: {exc}")

    return result


async def handle_proof_of_posession(
    profile: Profile, proof: Dict[str, Any], c_nonce: str | None = None
):
    """Handle proof of posession."""
    encoded_headers, encoded_payload, encoded_signature = proof["jwt"].split(".", 3)
    headers = b64_to_dict(encoded_headers)

    # OID4VCI 1.0 requires typ="openid4vci-proof+jwt"
    # But accept common draft spec values for backward compatibility
    typ = headers.get("typ")
    valid_typ_values = ["openid4vci-proof+jwt", "JWT", "jwt", "openid4vci-jwt"]
    if typ and typ not in valid_typ_values:
        LOGGER.warning("Proof JWT has unexpected typ header: %s", typ)
        raise web.HTTPBadRequest(
            text=json.dumps(
                {
                    "error": "invalid_proof",
                    "error_description": f"unsupported typ: {typ}",
                }
            ),
            content_type="application/json",
        )

    if "jwk" in headers:
        # Prefer inline JWK over kid-based DID resolution (OID4VCI spec §7.2.1).
        # Wallets such as walt.id send both kid and jwk in the proof header;
        # resolving the kid as a DID URL fails when the key is not registered in
        # a resolvable DID document, causing a spurious "invalid kid in proof".
        key = Key.from_jwk(headers["jwk"])
    elif "kid" in headers:
        try:
            key = await key_material_for_kid(profile, headers["kid"])
        except ValueError as exc:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "invalid kid in proof",
                    }
                ),
                content_type="application/json",
            ) from exc
    elif "x5c" in headers:
        # OID4VCI 1.0: wallet may use x5c (certificate-based) key binding.
        # Extract the public key from the leaf cert for signature verification.
        try:
            key = key_from_x5c(headers["x5c"])
        except Exception as exc:
            LOGGER.debug("Failed to extract key from x5c cert chain: %s", exc)
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "invalid x5c certificate in proof header",
                    }
                ),
                content_type="application/json",
            ) from exc
    else:
        # No key material in the header. Some draft-era wallets (e.g. walt.id)
        # omit jwk/kid/x5c from the proof header and instead put the DID in the
        # payload `iss` claim. Decode the payload first and attempt resolution.
        payload_for_iss = b64_to_dict(encoded_payload)
        iss = payload_for_iss.get("iss")
        if iss:
            # key_material_for_kid expects a DID URL (with fragment), not a bare
            # DID.  For did:jwk and did:key the first verification method is #0.
            kid_url = iss if "#" in iss else f"{iss}#0"
            try:
                key = await key_material_for_kid(profile, kid_url)
                LOGGER.debug("Resolved proof key from payload iss: %s", iss)
            except (ValueError, Exception) as exc:
                LOGGER.debug("Could not resolve key from iss '%s': %s", iss, exc)
                raise web.HTTPBadRequest(
                    text=json.dumps(
                        {
                            "error": "invalid_proof",
                            "error_description": "no key material in proof header and"
                            " iss could not be resolved",
                        }
                    ),
                    content_type="application/json",
                ) from exc
        else:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": "no key material in proof header",
                    }
                ),
                content_type="application/json",
            )

    payload = b64_to_dict(encoded_payload)

    # OID4VCI 1.0 § 7.2.2: the proof JWT MUST contain an `aud` claim equal to
    # the Credential Issuer Identifier (the issuer's base URL).  Omitting this
    # check allows proof replay across issuers.
    aud = payload.get("aud")
    if aud is not None:
        issuer_endpoint = Config.from_settings(profile.settings).endpoint
        # aud may be a string or a list of strings (per RFC 7519 § 4.1.3)
        aud_values = [aud] if isinstance(aud, str) else list(aud)

        def _strip_default_port(url: str) -> str:
            """Remove explicit default ports (https:443, http:80) for comparison."""
            try:
                p = urlparse(url)
                if (p.scheme == "https" and p.port == 443) or (
                    p.scheme == "http" and p.port == 80
                ):
                    netloc = p.hostname or ""
                    return p._replace(netloc=netloc).geturl()
            except Exception:
                pass
            return url

        norm_endpoint = _strip_default_port(issuer_endpoint) if issuer_endpoint else ""
        if issuer_endpoint and not any(
            _strip_default_port(av) == norm_endpoint
            or _strip_default_port(av).startswith(norm_endpoint + "/tenant/")
            for av in aud_values
        ):
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_proof",
                        "error_description": (
                            f"proof JWT aud '{aud}' does not match "
                            f"issuer endpoint '{issuer_endpoint}'"
                        ),
                    }
                ),
                content_type="application/json",
            )

    # OID4VCI 1.0 final spec uses "nonce"; older draft wallets may use "c_nonce".
    nonce = payload.get("nonce") or payload.get("c_nonce")
    if c_nonce:
        if c_nonce != nonce:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_nonce",
                        "error_description": "nonce mismatch",
                    }
                ),
                content_type="application/json",
            )
    else:
        # OID4VCI 1.0: nonce was obtained from the /nonce endpoint.
        # Open a session to redeem it (marks it used for replay protection).
        async with profile.session() as session:
            redeemed = await Nonce.redeem_by_value(session, nonce)
        if not redeemed:
            raise web.HTTPBadRequest(
                text=json.dumps(
                    {
                        "error": "invalid_nonce",
                        "error_description": "invalid or already-used nonce",
                    }
                ),
                content_type="application/json",
            )

    decoded_signature = b64_to_bytes(encoded_signature, urlsafe=True)
    verified = key.verify_signature(
        f"{encoded_headers}.{encoded_payload}".encode(),
        decoded_signature,
        sig_type=headers.get("alg", ""),
    )

    # If the wallet sent a kid-based proof (no jwk in header), derive the public
    # JWK from the resolved key so credential processors that need the raw JWK
    # (e.g. mso_mdoc for holder key binding in DeviceKey) can access it.
    holder_jwk = headers.get("jwk")
    if holder_jwk is None and (
        "kid" in headers or not any(k in headers for k in ("jwk", "kid", "x5c"))
    ):
        try:
            holder_jwk = json.loads(key.get_jwk_public())
        except Exception:
            LOGGER.debug("Could not derive holder JWK from resolved key")

    return PopResult(
        headers,
        payload,
        verified,
        holder_kid=headers.get("kid"),
        holder_jwk=holder_jwk,
        holder_x5c=headers.get("x5c"),
    )
