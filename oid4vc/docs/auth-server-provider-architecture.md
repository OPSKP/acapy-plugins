# Pluggable Authorization Server Providers

> Status: **Proposed** · Branch: `POC_Keycloak_integration`
>
> Replaces the `auth_type == "keycloak"` vs reference-AS `if/else` branching in
> the OID4VCI request path with an injectable provider abstraction, mirroring the
> existing `CredProcessors` pattern used for credential formats (mDoc, SD-JWT, …).

## 1. Problem

The Keycloak POC works by branching on `auth_server.get("auth_type") == "keycloak"`
throughout the issuance path. That was fine for a spike but is not maintainable:
the AS-specific logic is scattered, the core code imports Keycloak-specific
helpers, and adding a third AS means touching every branch point.

### Where the branching lives today

| Seam | File | Keycloak | Reference AS | No external AS |
|---|---|---|---|---|
| Mint pre-authorized code | `routes/helpers.py` `_create_pre_auth_code` | ROPC → `create-credential-offer` → fetch offer → extract JWT code | POST `/grants/pre-authorized-code` | `secrets.token_urlsafe` |
| Validate access token | `public_routes/token.py` `check_token` | local JWKS verify (`_verify_keycloak_jwt`) | `/introspect` | ACA-Py `jwt_verify` |
| Exchange-record key | `routes/helpers.py` `_parse_cred_offer`, `public_routes/credential.py` `issue_cred` | `credentials_offer_id` from code JWT / `authorization_details` | token `sub` | token `sub` |
| Client→AS auth header | `utils.py` `get_auth_header` | folded into `client_secret_basic` | `client_secret_basic` / `client_secret_jwt` / `private_key_jwt` | n/a |
| Provision credential type | `routes/helpers.py` `ensure_keycloak_scope`, called from each format's routes (`jwt_vc_json`, `sd_jwt_vc`, `mso_mdoc`) | create + assign Keycloak client scope via Admin API | no-op | no-op |
| AS record bootstrap | `utils.py` `get_first_auth_server` | env-var fallback | DB record | returns `None` |

### Key insight: `auth_type` is overloaded

`auth_type` currently conflates **two orthogonal concepts**:

1. **AS integration flavor** — which AS protocol dialect to speak (`keycloak`
   vs the ACA-Py reference AS).
2. **Client authentication method** — how the issuer authenticates *to* the AS
   (`client_secret_basic`, `client_secret_jwt`, `private_key_jwt`).

The new design splits these: a **provider** selects the integration; the
client-auth method becomes provider sub-config.

## 2. Design

A registry, bound into the ACA-Py injector, maps an authorization-server record
to an `AuthServerProvider`. This is the same shape as
`oid4vc.cred_processor.CredProcessors`, which maps a credential `format` to an
`Issuer`/`Verifier` and is populated by each format plugin's `setup()`.

```
                         ┌──────────────────────────────┐
   request path  ───────▶│      AuthServerRegistry      │  (bound in injector)
 (token / helpers /      │  provider_for(auth_server)   │
  credential / format    └───────────────┬──────────────┘
  routes)                                 │ selects by record["provider"]
                       ┌──────────────────┼───────────────────┐
                       ▼                  ▼                   ▼
              InternalProvider   AcapyReferenceProvider   KeycloakProvider
              (core, default)    (core)                   (external plugin)
```

### The provider interface

```python
class AuthServerProvider(Protocol):
    async def create_pre_authorized_code(
        self, ctx: AuthContext, request: PreAuthCodeRequest
    ) -> PreAuthCodeResult: ...

    async def validate_access_token(
        self, ctx: AuthContext, token: str, scheme: str
    ) -> TokenValidationResult: ...    # == JWTVerifyResult

    def resolve_exchange_key(
        self, payload: Mapping[str, Any], code: str | None
    ) -> str | None:                   # None ⇒ use token `sub`
        ...

    async def on_supported_credential_registered(
        self, ctx: AuthContext, record: SupportedCredential
    ) -> None: ...
```

- **`AuthContext`** bundles the recurring args (`profile`, `config`,
  `auth_server` record) so method signatures stay small.
- **`PreAuthCodeResult`** carries the `code` *plus* an optional `exchange_key`,
  folding the `_parse_cred_offer` `refresh_id` mutation into the result instead
  of a second `if`.
- **`TokenValidationResult`** is aliased to the existing `JWTVerifyResult`, so
  providers drop straight into `check_token` with no translation layer.

### The "no external AS" path becomes a provider too

The biggest simplification: the current `else` branches (`secrets.token_urlsafe`,
`jwt_verify`) are not special cases — they are the **`InternalProvider`**. So
every call site collapses to *resolve provider → call method*, with **zero**
`if auth_type`:

```python
# check_token (token.py)
provider = registry.provider_for(auth_server)
result = await provider.validate_access_token(ctx, cred, scheme)
if scheme.lower() == "dpop":      # DPoP stays SHARED — RFC 9449, not AS-specific
    _validate_dpop(...); _check_cnf_jkt(result.payload, dpop_proof)

# _create_pre_auth_code (helpers.py)
res = await provider.create_pre_authorized_code(ctx, req)
record.code = res.code
if res.exchange_key:
    record.refresh_id = res.exchange_key

# format routes (jwt_vc_json / sd_jwt_vc / mso_mdoc)
await provider.on_supported_credential_registered(ctx, record)
```

### Cross-cutting concerns stay out of providers

DPoP proof validation (`_validate_dpop`, `_verify_sig_with_jwk`,
`_jwk_thumbprint`, `_b64url_to_int`) is **RFC 9449**, not AS-specific — both
external and internal tokens can be DPoP-bound. It moves to a shared
`dpop.py` / `jwk_utils.py` module and is applied by `check_token` *after* the
provider validates the token. Likewise JWKS fetching helpers are shared utilities
a provider may call, not part of the protocol.

## 3. Packaging

Built-in providers live in core `oid4vc`; the Keycloak integration ships as its
**own installable plugin**, exactly like `mso_mdoc`/`sd_jwt_vc`.

```
oid4vc/oid4vc/auth_providers/      # core
    __init__.py                    # re-exports
    base.py                        # protocol, AuthContext, result dataclasses
    registry.py                    # AuthServerRegistry
    internal.py                    # InternalProvider  (no external AS)
    acapy_reference.py             # AcapyReferenceProvider  (step 2)
oid4vc/auth_keycloak/              # SEPARATE plugin (like oid4vc/mso_mdoc/)
    auth_keycloak/__init__.py      # setup() registers KeycloakProvider
    auth_keycloak/provider.py      # KeycloakProvider (ROPC, JWKS, scope sync)
    pyproject.toml
```

> Naming note: the subpackage is `auth_providers` (issuer-side AS integrations),
> deliberately distinct from the existing standalone `oid4vc/auth_server/`
> service (the reference AS implementation itself).

### Registration (mirrors `mso_mdoc/__init__.py`)

```python
# oid4vc/oid4vc/__init__.py  (core setup)
auth_registry = AuthServerRegistry()
auth_registry.register("internal", InternalProvider())
auth_registry.register("acapy", AcapyReferenceProvider())   # step 2
context.injector.bind_instance(AuthServerRegistry, auth_registry)

# oid4vc/auth_keycloak/auth_keycloak/__init__.py  (only when plugin is loaded)
async def setup(context):
    registry = context.inject_or(AuthServerRegistry) or AuthServerRegistry()
    registry.register("keycloak", KeycloakProvider())
    context.injector.bind_instance(AuthServerRegistry, registry)
```

Core `oid4vc` ends up with **no** Keycloak knowledge — the same way it has no
mDoc knowledge today.

## 4. Config & record model

- Rename the discriminator on the `IssuerConfiguration.authorization_servers`
  record from `auth_type` → `provider` (`"keycloak" | "acapy" | "internal"`),
  and add a separate `client_auth_method`
  (`client_secret_basic | client_secret_jwt | private_key_jwt`) that the provider
  consumes. This de-overloads `get_auth_header`.
- `Config` already carries `auth_server_type/url/client` (env bootstrap); map
  `auth_server_type → provider`.
- Migration: existing `auth_type=client_secret_basic` records map to
  `provider=acapy`, `client_auth_method=client_secret_basic`. The registry reads
  `provider` and falls back to `auth_type` during the transition.

## 5. Rollout (reviewable PR slices)

1. **Provider abstraction + `InternalProvider`** (scaffolded on this branch:
   `oid4vc/oid4vc/auth_providers/`). Bind the registry in `setup()`; route the
   no-AS path through it. Pure refactor, no behavior change.
2. **`AcapyReferenceProvider`** — move grants-endpoint + introspection logic in;
   delete those `if/else` arms.
3. **Extract shared DPoP / JWK utilities** out of `token.py`.
4. **`auth_keycloak` plugin** — move all Keycloak code into its own package;
   register via `setup()`.
5. **Record-model split** (`provider` / `client_auth_method`) + migration + docs.

## 6. Decisions & open questions

- **Reference-AS provider home:** kept in core `oid4vc` as the default (always
  available), not split into its own plugin. (Lean; revisit if it grows.)
- **Scope-sync trigger:** today each format route calls `ensure_keycloak_scope`.
  Proposed: route those calls to `provider.on_supported_credential_registered`.
  Open question: keep per-format calls, or replace with a single event
  subscription on "SupportedCredential created" (removes the import from all
  three format routes)?
- **Issuer metadata:** a provider *could* own `authorization_servers` /
  `token_endpoint` in issuer metadata via an optional
  `contribute_issuer_metadata(metadata, ctx)` hook — **deferred** to avoid
  colliding with the in-flight `metadata.py` fix by another developer.
