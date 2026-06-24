"""Helper functions for OID4VC routes."""

import logging
import secrets
from urllib.parse import urlparse

LOGGER = logging.getLogger(__name__)

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.storage.error import StorageError
from aiohttp import web

from ..app_resources import AppResources
from ..config import Config
from ..models.exchange import OID4VCIExchangeRecord
from ..models.supported_cred import SupportedCredential
from ..utils import (
    get_auth_header,
    get_auth_server_url,
    get_first_auth_server,
    get_tenant_subpath,
)

CODE_BYTES = 32


async def _create_pre_auth_code(
    profile: Profile,
    config: Config,
    auth_server: dict | None,
    subject_id: str,
    credential_configuration_id: str | None = None,
    user_pin: str | None = None,
) -> str:
    """Create a secure random pre-authorized code."""

    if auth_server:
        auth_type = auth_server.get("auth_type", "")
        private_url = get_auth_server_url(auth_server)
        client_creds = auth_server.get("client_credentials", {})

        if auth_type == "keycloak":
            # Keycloak OID4VCI pre-authorized code flow:
            # 1. Get a user token via ROPC with the credential scope.
            #    Requires Keycloak ≥ 26.4 (OIDC clients accept oid4vc scopes).
            username = client_creds.get("username", "")
            password = client_creds.get("password", "")
            scope = f"openid {credential_configuration_id}"

            # When Keycloak is behind a proxy (e.g. ngrok), the pre-authorized
            # code JWT's aud is set to the URL Keycloak thinks it's running on.
            # Pass X-Forwarded-* headers so Keycloak uses the public URL in the
            # JWT aud, which must match when the wallet redeems the code.
            public_url = auth_server.get("public_url") or private_url
            parsed_public = urlparse(public_url)
            forwarded_headers = {
                "X-Forwarded-Proto": parsed_public.scheme,
                "X-Forwarded-Host": parsed_public.netloc,
            }

            token_resp = await AppResources.get_http_client().post(
                f"{private_url}/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": client_creds["client_id"],
                    "client_secret": client_creds["client_secret"],
                    "username": username,
                    "password": password,
                    "scope": scope,
                },
                headers=forwarded_headers,
            )
            if token_resp.status != 200:
                body = await token_resp.text()
                raise web.HTTPBadGateway(
                    reason=f"Keycloak ROPC token request failed {token_resp.status}: {body}"
                )
            token_data = await token_resp.json()
            user_token = token_data["access_token"]

            # 2. Call create-credential-offer with pre_authorized=true to get a nonce.
            params: dict = {
                "credential_configuration_id": credential_configuration_id,
                "pre_authorized": "true",
            }
            if username:
                params["target_user"] = username
            if user_pin is not None:
                params["tx_code"] = user_pin
            offer_uri_resp = await AppResources.get_http_client().get(
                f"{private_url}/protocol/oid4vc/create-credential-offer",
                params=params,
                headers={"Authorization": f"Bearer {user_token}", **forwarded_headers},
            )
            if offer_uri_resp.status != 200:
                body = await offer_uri_resp.text()
                raise web.HTTPBadGateway(
                    reason=f"Keycloak create-credential-offer failed {offer_uri_resp.status}: {body}"
                )
            offer_uri_data = await offer_uri_resp.json()
            LOGGER.warning("Keycloak create-credential-offer response: %s", offer_uri_data)
            nonce = offer_uri_data.get("nonce")
            if not nonce:
                raise web.HTTPBadGateway(
                    reason="Keycloak create-credential-offer returned no nonce"
                )

            # Since Keycloak 26.4 the pre-authorized code is a stateless JWT
            # (PR #46450). The JWT itself is the code — no second fetch needed.
            # For older auth-code offers the nonce is an opaque base64url string
            # with no dots; those still require a second fetch.
            if "." in nonce:
                # nonce IS the JWT pre-authorized code
                code = nonce
            else:
                # 3. Fetch the full credential offer using the opaque nonce.
                offer_resp = await AppResources.get_http_client().get(
                    f"{private_url}/protocol/oid4vc/credential-offer/{nonce}",
                    headers={"Authorization": f"Bearer {user_token}", **forwarded_headers},
                )
                if offer_resp.status != 200:
                    body = await offer_resp.text()
                    raise web.HTTPBadGateway(
                        reason=f"Keycloak credential-offer fetch failed {offer_resp.status}: {body}"
                    )
                offer_data = await offer_resp.json()
                LOGGER.warning(
                    "Keycloak credential-offer/%s response: %s", nonce, offer_data
                )
                grants = offer_data.get("grants", {})
                pre_auth_grant = grants.get(
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code", {}
                )
                code = pre_auth_grant.get("pre-authorized_code") or pre_auth_grant.get(
                    "pre_authorized_code"
                )
                if not code:
                    raise web.HTTPBadGateway(
                        reason="Keycloak credential offer contained no pre-authorized_code"
                    )
        else:
            subpath = get_tenant_subpath(profile, tenant_prefix="/tenant")
            issuer_server_url = f"{config.endpoint}{subpath}"
            grants_endpoint = f"{private_url}/grants/pre-authorized-code"
            auth_header = await get_auth_header(
                profile, auth_server, issuer_server_url, grants_endpoint
            )
            user_pin_required = user_pin is not None
            resp = await AppResources.get_http_client().post(
                grants_endpoint,
                json={
                    "subject_id": subject_id,
                    "user_pin_required": user_pin_required,
                    "user_pin": user_pin,
                    "authorization_details": [
                        {
                            "type": "openid_credential",
                            "credential_configuration_id": credential_configuration_id,
                        }
                    ],
                },
                headers={"Authorization": f"{auth_header}"},
            )
            if resp.status != 200:
                body = await resp.text()
                raise web.HTTPBadGateway(
                    reason=f"Auth server returned {resp.status}: {body}"
                )
            data = await resp.json()
            code = data["pre_authorized_code"]
    else:
        code = secrets.token_urlsafe(CODE_BYTES)
    return code


async def _parse_cred_offer(context: AdminRequestContext, exchange_id: str) -> dict:
    """Helper function for cred_offer request parsing.

    Used in get_cred_offer and public_routes.dereference_cred_offer endpoints.
    """
    config = Config.from_settings(context.settings)
    try:
        async with context.session() as session:
            record = await OID4VCIExchangeRecord.retrieve_by_id(session, exchange_id)
            supported = await SupportedCredential.retrieve_by_id(
                session, record.supported_cred_id
            )
            auth_server = await get_first_auth_server(session, context.profile)
            record.code = await _create_pre_auth_code(
                context.profile,
                config,
                auth_server,
                record.refresh_id,
                supported.identifier,
                record.pin,
            )
            # For Keycloak, the access token's sub is the Keycloak user UUID
            # (not the ACA-Py refresh_id). Update refresh_id to match so that
            # retrieve_by_refresh_id succeeds at credential issuance time.
            if (
                auth_server
                and auth_server.get("auth_type") == "keycloak"
                and record.code
                and "." in record.code
            ):
                try:
                    _, payload_b64, _ = record.code.split(".")
                    pre_auth_payload = b64_to_dict(payload_b64)
                    kc_offer_id = pre_auth_payload.get("context", {}).get(
                        "credentials_offer_id"
                    )
                    if kc_offer_id:
                        record.refresh_id = kc_offer_id
                except Exception:
                    pass
            record.state = OID4VCIExchangeRecord.STATE_OFFER_CREATED
            await record.save(session, reason="Credential offer created")
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    user_pin_required: bool = record.pin is not None
    wallet_id = (
        context.profile.settings.get("wallet.id")
        if context.profile.settings.get("multitenant.enabled")
        else None
    )
    subpath = f"/tenant/{wallet_id}" if wallet_id else ""
    pre_auth_grant: dict = {
        "pre-authorized_code": record.code,
    }
    if user_pin_required:
        # OID4VCI 1.0 final: tx_code replaces user_pin_required in the offer.
        # Indicate that a transaction code is required without revealing the value.
        pre_auth_grant["tx_code"] = {"input_mode": "text"}
    return {
        "credential_issuer": f"{config.endpoint}{subpath}",
        "credential_configuration_ids": [supported.identifier],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": pre_auth_grant,
        },
    }


async def ensure_keycloak_scope(
    profile: Profile,
    record: SupportedCredential,
    auth_server: dict,
) -> None:
    """Create a Keycloak OID4VC client scope for a SupportedCredential if absent.

    Uses the acapy-issuer service account (client_credentials grant) to call the
    Keycloak Admin REST API. The service account must have the 'manage-clients'
    role on the 'realm-management' client in Keycloak.

    Silently logs warnings on failure — scope sync is best-effort.
    """
    private_url = get_auth_server_url(auth_server)
    client_creds = auth_server.get("client_credentials", {})

    # Parse base URL and realm from e.g. http://keycloak:8080/realms/oid4vc-demo
    parsed = urlparse(private_url)
    path_parts = [p for p in parsed.path.split("/") if p]
    if len(path_parts) < 2 or path_parts[-2] != "realms":
        LOGGER.warning("Cannot parse Keycloak realm URL: %s", private_url)
        return
    realm = path_parts[-1]
    kc_base = f"{parsed.scheme}://{parsed.netloc}"
    admin_base = f"{kc_base}/admin/realms/{realm}"

    # Get service account token via client_credentials grant
    token_resp = await AppResources.get_http_client().post(
        f"{private_url}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_creds["client_id"],
            "client_secret": client_creds["client_secret"],
        },
    )
    if token_resp.status != 200:
        body = await token_resp.text()
        LOGGER.warning("Keycloak scope sync: failed to get service account token: %s", body)
        return
    admin_token = (await token_resp.json())["access_token"]
    auth_headers = {"Authorization": f"Bearer {admin_token}"}

    # Build scope attributes from the SupportedCredential format
    scope_attrs: dict = {
        "vc.credential_configuration_id": record.identifier,
        "vc.expiry_in_seconds": "31536000",
        "vc.format": record.format,
    }
    if record.format == "vc+sd-jwt" and record.format_data:
        vct = record.format_data.get("vct")
        if vct:
            scope_attrs["vc.vct"] = vct

    # Create the client scope (409 = already exists, which is fine)
    create_resp = await AppResources.get_http_client().post(
        f"{admin_base}/client-scopes",
        json={"name": record.identifier, "protocol": "oid4vc", "attributes": scope_attrs},
        headers=auth_headers,
    )
    if create_resp.status == 409:
        LOGGER.info("Keycloak scope '%s' already exists", record.identifier)
    elif create_resp.status not in (200, 201):
        body = await create_resp.text()
        LOGGER.warning(
            "Keycloak scope sync: failed to create scope '%s': %s %s",
            record.identifier, create_resp.status, body,
        )
        return
    else:
        LOGGER.info("Keycloak scope '%s' created", record.identifier)

    # Resolve scope ID
    scopes_resp = await AppResources.get_http_client().get(
        f"{admin_base}/client-scopes", headers=auth_headers
    )
    if scopes_resp.status != 200:
        LOGGER.warning("Keycloak scope sync: failed to list scopes")
        return
    scope_id = next(
        (s["id"] for s in await scopes_resp.json() if s["name"] == record.identifier),
        None,
    )
    if not scope_id:
        LOGGER.warning("Keycloak scope sync: scope '%s' not found after create", record.identifier)
        return

    # Resolve client internal ID
    clients_resp = await AppResources.get_http_client().get(
        f"{admin_base}/clients",
        params={"clientId": client_creds["client_id"]},
        headers=auth_headers,
    )
    if clients_resp.status != 200 or not (clients := await clients_resp.json()):
        LOGGER.warning("Keycloak scope sync: failed to find client '%s'", client_creds["client_id"])
        return
    kc_client_id = clients[0]["id"]

    # Assign scope as optional to the client
    assign_resp = await AppResources.get_http_client().put(
        f"{admin_base}/clients/{kc_client_id}/optional-client-scopes/{scope_id}",
        headers=auth_headers,
    )
    if assign_resp.status in (200, 204):
        LOGGER.info(
            "Keycloak scope '%s' assigned as optional to client '%s'",
            record.identifier, client_creds["client_id"],
        )
    else:
        body = await assign_resp.text()
        LOGGER.warning("Keycloak scope sync: failed to assign scope: %s %s", assign_resp.status, body)
