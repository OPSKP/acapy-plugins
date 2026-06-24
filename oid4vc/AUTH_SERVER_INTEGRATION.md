# Third-Party Authorization Server Integration

This document describes how the OID4VC plugin delegates authorization to an external
Authorization Server (AS), using Keycloak as the reference implementation.

## Overview

By default the plugin acts as its own AS: it generates pre-authorized codes locally,
issues access tokens from its `/token` endpoint, and verifies them with its own keys.

When an external AS is configured, the plugin delegates three responsibilities:

| Responsibility | Default (no AS) | With external AS |
|---|---|---|
| Pre-authorized code generation | `secrets.token_urlsafe()` locally | AS generates the code |
| Token issuance | Plugin `/token` endpoint | AS token endpoint |
| Token verification | Local JWT verification | Local JWKS verification (Keycloak) or AS introspection |

Everything else — credential signing, proof-of-possession verification, DPoP binding,
credential metadata — remains in the plugin.

## How It Works

### Pre-Authorized Code Flow with External AS

```mermaid
sequenceDiagram
    actor Controller
    participant Plugin as Plugin (ACA-Py)
    participant AS as AS (Keycloak)
    actor Wallet

    Controller->>Plugin: POST /exchange/credential-offer
    Plugin->>AS: POST /token (ROPC, credential scope)
    AS-->>Plugin: user access token
    Plugin->>AS: GET /create-credential-offer?pre_authorized=true
    AS-->>Plugin: { nonce: JWT (pre-auth code) }
    Plugin-->>Controller: credential offer URI

    Note over Controller,Wallet: QR code displayed to user

    Wallet->>Plugin: GET /.well-known/openid-credential-issuer
    Plugin-->>Wallet: metadata (authorization_servers: [AS public URL])

    Wallet->>AS: GET /.well-known/openid-configuration
    AS-->>Wallet: AS metadata (token_endpoint, jwks_uri, …)

    Wallet->>AS: POST /token (pre-auth code)
    AS-->>Wallet: DPoP-bound access token

    Wallet->>Plugin: POST /credential (Authorization: DPoP <token>, DPoP: <proof>)
    Plugin->>AS: GET /certs (fetch JWKS)
    AS-->>Plugin: JWKS
    Note over Plugin: Verify token signature & expiry<br/>Validate DPoP proof (RFC 9449)<br/>Verify proof of possession
    Plugin-->>Wallet: credential response
```

### Plugin Endpoints Affected

| Endpoint | Behaviour change |
|---|---|
| `/.well-known/openid-credential-issuer` | Adds `authorization_servers: [AS public URL]` |
| `GET /oid4vci/credential-offer` | Calls AS to obtain the pre-authorized code; `safe=''` URL encoding |
| `GET /oid4vci/credential-offer-by-ref` | Returns `credential_offer_uri=` (by-reference); wallet fetches offer via `/oid4vci/dereference-credential-offer` |
| `POST /token` | Returns `400` — wallets must use the AS token endpoint directly |
| `POST /credential` | Validates token via JWKS (Keycloak) or introspection; validates DPoP proof |

---

## Configuration

### Option A — IssuerConfiguration API (per-tenant, database-driven)

```http
PUT /oid4vci/issuer/configuration
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "authorization_servers": [
    {
      "public_url":  "https://keycloak.example.com/realms/oid4vc-demo",
      "private_url": "http://keycloak:8080/realms/oid4vc-demo",
      "auth_type":   "keycloak",
      "client_credentials": {
        "client_id":     "acapy-issuer",
        "client_secret": "acapy-issuer-secret",
        "username":      "demo-user",
        "password":      "demo-password"
      }
    }
  ]
}
```

- **`public_url`** — advertised to wallets in credential issuer metadata and used as the
  `X-Forwarded-Host` origin when the plugin calls Keycloak internally, so Keycloak embeds
  the public URL in issued JWTs.
- **`private_url`** — used for all internal HTTP calls from the plugin to Keycloak (useful
  when Keycloak is on a private Docker network). Defaults to `public_url` if omitted.
- **`username` / `password`** — Keycloak user whose identity is embedded in the
  pre-authorized code offer (ROPC flow).  Must correspond to a Keycloak user that has the
  `credential-offer-create` realm role and the relevant credential scopes available.

### Option B — Environment Variables (global fallback)

When no `IssuerConfiguration` record exists for a wallet:

| Variable | Description | Example |
|---|---|---|
| `OID4VCI_AUTH_SERVER_URL` | Keycloak realm URL | `http://keycloak:8080/realms/oid4vc-demo` |
| `OID4VCI_AUTH_SERVER_TYPE` | AS type | `keycloak` |
| `OID4VCI_AUTH_SERVER_CLIENT` | JSON with client + user credentials | `{"client_id":"acapy-issuer","client_secret":"acapy-issuer-secret","username":"demo-user","password":"demo-password"}` |

### Supported `auth_type` Values

| `auth_type` | Token verification | Pre-auth code |
|---|---|---|
| `keycloak` | Local JWKS validation (see below) | ROPC + `create-credential-offer` |
| `client_secret_basic` | AS `/introspect` with Basic auth | AS `/grants/pre-authorized-code` |
| `client_secret_jwt` | AS `/introspect` with HMAC JWT | AS `/grants/pre-authorized-code` |
| `private_key_jwt` | AS `/introspect` with asymmetric JWT | AS `/grants/pre-authorized-code` |

---

## Keycloak Integration

### Requirements

- Keycloak **26.4 or later**
- Feature flags: `KC_FEATURES: oid4vc-vci,oid4vc-vci-preauth-code`
- Behind a TLS-terminating proxy (ngrok, load balancer): `KC_PROXY_HEADERS: xforwarded`

### Pre-Authorized Code Flow (Keycloak-specific)

Keycloak 26.4+ issues pre-authorized codes as stateless HS512-signed JWTs
(see Keycloak PR #46450).  The plugin uses a two-step ROPC flow:

**Step 1 — Obtain a user access token (ROPC)**

```
POST {private_url}/protocol/openid-connect/token
X-Forwarded-Proto: https
X-Forwarded-Host:  <keycloak-public-hostname>

grant_type=password
client_id=acapy-issuer
client_secret=acapy-issuer-secret
username=demo-user
password=demo-password
scope=openid IDCard
```

The `X-Forwarded-*` headers are injected so Keycloak uses the public hostname when
embedding `iss` / `aud` in the resulting JWT.

**Step 2 — Create a credential offer**

```
GET {private_url}/protocol/oid4vc/create-credential-offer
Authorization: Bearer <user access token>
X-Forwarded-Proto: https
X-Forwarded-Host:  <keycloak-public-hostname>

?credential_configuration_id=IDCard
&pre_authorized=true
&target_user=demo-user
```

The response contains `{ "nonce": "<JWT>" }`.  Since Keycloak 26.4 this nonce **is**
the pre-authorized code (a JWT with `context.target_user_id`).  The plugin detects
this by checking for `.` in the nonce; older opaque nonces trigger a second
`GET /protocol/oid4vc/credential-offer/{nonce}` fetch to extract the code.

**Exchange record lookup alignment**

The exchange record's `refresh_id` is updated to `context.credentials_offer_id` from
the pre-authorized code JWT.  This value is unique per credential offer and is
carried forward in the wallet's access token as
`authorization_details[0].credentials_offer_id`.

At issuance time, the credential endpoint extracts `credentials_offer_id` from the
token's `authorization_details` and uses it as the lookup key.  This is more precise
than using `sub` (the Keycloak user UUID), which is shared across all active offers
for the same user and would cause ambiguous lookups when a user has multiple concurrent
credential exchanges (e.g., IDCard and mDL).

### Token Verification (Keycloak-specific)

Keycloak's OID4VCI access tokens are **DPoP-bound** with `aud` set to Keycloak's own
credential endpoint URL.  Standard token introspection fails because `acapy-issuer`
is not in that audience.

The plugin validates Keycloak tokens locally instead:

1. Fetches JWKS from `{private_url}/protocol/openid-connect/certs`
2. Verifies the token's JWT signature (RSA RS*/PS*, EC ES*, OKP EdDSA)
3. Checks token expiry

### DPoP Proof Validation (RFC 9449)

For `Authorization: DPoP <token>` requests, the plugin performs full DPoP binding
validation after the access token is verified:

| Check | Description |
|---|---|
| `typ` | Must be `dpop+jwt` |
| `alg` | Must be a non-`none` asymmetric algorithm |
| `jwk` | Embedded public key must be present in the proof header |
| `htm` | Must match the HTTP method of the credential request |
| `htu` | Must match the public URI of the credential endpoint (scheme + host + path, no query) |
| `iat` | Must be within ±300 seconds of current time |
| `ath` | Must equal `BASE64URL(SHA-256(access_token))` |
| Signature | Verified using the embedded `jwk` |
| `cnf.jkt` | JWK thumbprint (RFC 7638) of the proof key must match the `cnf.jkt` claim in the access token |

The credential endpoint reconstructs the public URI from `X-Forwarded-Proto` and
`X-Forwarded-Host` headers (set by ngrok/proxy) so the `htu` comparison uses the
wallet-facing URL rather than the internal Docker hostname.

> **Note:** `jti` replay protection is not yet implemented.

### Keycloak Realm Configuration

```json
{
  "realm": "oid4vc-demo",
  "enabled": true,
  "verifiableCredentialsEnabled": true,
  "attributes": {
    "oid4vc.pre-authorized-code-lifespan": "300"
  },
  "roles": {
    "realm": [
      { "name": "credential-offer-create" }
    ]
  },
  "clientScopes": [
    {
      "name": "IDCard",
      "protocol": "oid4vc",
      "attributes": {
        "vc.format": "vc+sd-jwt",
        "vc.vct": "ExampleIDCard",
        "vc.credential_configuration_id": "IDCard",
        "vc.expiry_in_seconds": "31536000"
      }
    }
  ],
  "clients": [
    {
      "clientId": "acapy-issuer",
      "enabled": true,
      "publicClient": false,
      "serviceAccountsEnabled": true,
      "directAccessGrantsEnabled": true,
      "secret": "acapy-issuer-secret",
      "standardFlowEnabled": false,
      "attributes": { "oid4vci.enabled": "true" },
      "optionalClientScopes": ["IDCard"]
    }
  ],
  "users": [
    {
      "username": "service-account-acapy-issuer",
      "enabled": true,
      "serviceAccountClientId": "acapy-issuer",
      "realmRoles": ["credential-offer-create"],
      "clientRoles": {
        "realm-management": ["manage-clients", "view-clients"]
      }
    },
    {
      "username": "demo-user",
      "enabled": true,
      "credentials": [{ "type": "password", "value": "demo-password", "temporary": false }],
      "realmRoles": ["credential-offer-create"]
    }
  ]
}
```

**Key points:**

- `verifiableCredentialsEnabled: true` — enables Keycloak's OID4VCI feature on the realm.
- `directAccessGrantsEnabled: true` — required for the ROPC flow used in step 1.
- `oid4vci.enabled: "true"` on the client — enables OID4VCI endpoints for this client.
- `optionalClientScopes` — credential types this client can offer. The scope name must
  match `vc.credential_configuration_id` and the `identifier` of the ACA-Py
  `SupportedCredential` record.
- `service-account-acapy-issuer` must have `manage-clients` + `view-clients` on
  `realm-management` to allow dynamic scope creation (see below).
- `demo-user` must have `credential-offer-create` to be a valid `target_user`.

### Dynamic Keycloak Scope Creation

When a new `SupportedCredential` is registered via any of the three
`POST /oid4vci/credential-supported/create/*` endpoints, the plugin automatically
creates the corresponding Keycloak client scope and assigns it to the `acapy-issuer`
client.

This uses the service account's `client_credentials` grant to call the Keycloak
Admin REST API:

1. `POST /admin/realms/{realm}/client-scopes` — create scope with `vc.format`,
   `vc.credential_configuration_id`, and `vc.vct` (SD-JWT only) attributes.
2. `GET /admin/realms/{realm}/client-scopes` — resolve the new scope's internal ID.
3. `GET /admin/realms/{realm}/clients?clientId=acapy-issuer` — resolve the client's
   internal ID.
4. `PUT /admin/realms/{realm}/clients/{id}/optional-client-scopes/{scopeId}` — assign
   the scope as optional to the client.

Failures are logged as warnings and do not prevent the credential from being registered
in ACA-Py.

### Docker Compose Setup

```yaml
services:

  keycloak:
    image: quay.io/keycloak/keycloak:26.6.2
    ports:
      - "9001:8080"
    environment:
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      KC_FEATURES: oid4vc-vci,oid4vc-vci-preauth-code
      KC_HTTP_ENABLED: "true"
      KC_HOSTNAME_STRICT: "false"
      KC_HEALTH_ENABLED: "true"
      KC_PROXY_HEADERS: xforwarded       # trust X-Forwarded-* from ngrok/proxy
    command: ["start-dev", "--import-realm"]
    volumes:
      - ./keycloak/realm-import.json:/opt/keycloak/data/import/realm-import.json:ro,z
    healthcheck:
      test: ["CMD", "bash", "-c", "exec 3<>/dev/tcp/localhost/9000"]
      start_period: 60s
      interval: 10s
      timeout: 5s
      retries: 15

  issuer:
    image: oid4vc
    environment:
      OID4VCI_AUTH_SERVER_URL:    http://keycloak:8080/realms/oid4vc-demo
      OID4VCI_AUTH_SERVER_TYPE:   keycloak
      OID4VCI_AUTH_SERVER_CLIENT: >
        {"client_id":"acapy-issuer","client_secret":"acapy-issuer-secret",
         "username":"demo-user","password":"demo-password"}
    depends_on:
      keycloak:
        condition: service_healthy
```

**`KC_PROXY_HEADERS: xforwarded`** is required when Keycloak is behind a TLS-terminating
reverse proxy (ngrok, nginx, etc.).  Without it, Keycloak builds all internal URLs with
`http://keycloak:8080/...` — these appear in JWT `iss`/`aud` claims, causing verification
failures when wallets hit the public HTTPS endpoint.

The plugin also injects `X-Forwarded-Proto` and `X-Forwarded-Host` headers (derived from
`auth_server.public_url`) into every internal call to Keycloak so the emitted JWTs always
reference the public URL.

---

## Adding a New AS Type

1. **`utils.get_auth_header`** — add an `elif auth_type == "your-type"` branch that
   returns the correct `Authorization` header value.

2. **`routes/helpers._create_pre_auth_code`** — add an `elif auth_type == "your-type"`
   branch that calls your AS's pre-authorized code endpoint and returns the code string.

3. **`public_routes/token.check_token`** — for non-Keycloak types the plugin calls
   `{private_url}/introspect`.  If your AS uses a different path, add a branch to
   compute `introspect_endpoint` accordingly.

4. Update the `auth_type` table in this document and in `IssuerConfigurationSchema`
   field metadata.
