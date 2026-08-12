---
title: Standards & conformance
description: Every RFC and specification this package implements, graded, with what is missing spelled out
weight: 8
---

# Standards & conformance

The RFC-by-RFC record of what `cboxdk/laravel-id` implements. For the non-protocol
capabilities (RBAC, governance, audit, webhooks, provisioning) see the
[feature support matrix](../capabilities/feature-support.md); for the short version see
[Capabilities](../capabilities/_index.md).

## When this was last checked against the code

Every **Partial** and **No** row states a specific, checkable limit, and a row whose limit
has quietly been fixed is worse than no row at all — it tells an adopter they cannot do
something they can. Verified claim by claim on 2026-08-11, with the inbound-OIDC-federation table
re-checked on 2026-08-12 when three of its rows changed; two rows were stale and are
corrected above:

- `AuthnContext` in a SAML assertion was hardcoded to `…ac:classes:Password` and is now
  derived from the session's `amr`.
- `id_token_signing_alg_values_supported` diverged from what issuance actually signed with
  and now reads the issuer's own constant.

The rest were re-read against `src/` and hold as written — including the ones easiest to
drift: PKCE `plain` is refused at issue time and redemption computes S256 regardless; revocation
calls `authenticateConfidential()`; there is no `DPoP-Nonce` anywhere in the package;
`resource` is read as a single string so a repeated parameter yields one value; and the
dynamic registrar's `AUTH_METHODS` is `none` / `client_secret_basic` / `client_secret_post`
with no `private_key_jwt`.

## How to read the grades

Every row is graded against code in **this package's `src/`**. Nothing is graded on
what the deployable app, an add-on package, or a future release does.

| Grade | What it means |
|---|---|
| **Full** | This package ships the whole capability as described, and its own test suite exercises it. |
| **Partial** | Usable, with a limit — and the limit is named in the row. A "partial" with no stated gap is a documentation bug; report it. |
| **Contract only** | The interface ships; the shipped default refuses or does nothing. Nothing works until you bind an implementation. |
| **Host-supplied** | This package ships the back-channel/protocol half. The interactive half — a screen, a redirect, a decision — is your application's to write. |
| **No** | Not implemented. Listed because adopters ask. |

> **The `/authorize` boundary — read this before the OAuth table.**
> This package is a library, not a running identity provider. It ships the
> **back-channel**: token, introspection, revocation, registration, PAR, device, CIBA,
> discovery, JWKS, plus the crypto and validation those enforce. It does **not** serve
> `/authorize`, and there is no login or consent screen in `src/`. Anything that happens
> *at* the authorization request — consent, `prompt`, `max_age`, `acr_values` gating,
> matching `redirect_uri` against the registered set, appending RFC 9207 `iss`, refusing a
> non-PAR request — is yours to implement, and is graded **Host-supplied** below.
> The [cbox-id app](../index.md) implements that half if you would rather not.
>
> PKCE is the one front-channel rule that holds regardless: an authorization code minted
> without a `code_challenge` can never satisfy the exchange, so a host that forgets to
> require PKCE fails closed rather than open.

## OAuth 2.0 (authorization server)

| Spec | What it covers | Grade | Notes |
|---|---|---|---|
| **RFC 6749** — The OAuth 2.0 Authorization Framework | Grants at `/oauth/token` | **Partial** | `authorization_code`, `client_credentials`, `refresh_token` implemented. **No** `password` (ROPC), **no** `implicit` — both refused as `unsupported_grant_type`. |
| **RFC 6750** — Bearer Token Usage | `Authorization: Bearer` on protected endpoints | **Full** | `bearer_methods_supported: ["header"]`; form/query delivery not accepted. |
| **RFC 7636** — PKCE | `code_challenge` / `code_verifier` | **Partial** | `S256` only, and only `S256` is advertised. `plain` is refused **at issue time** rather than being stored and failing later at redemption, so a host learns which end is wrong. The challenge must be a 43-character base64url digest and the verifier 43–128 unreserved characters (§4.1). Public-client enforcement is applied on `/oauth/par`; at `/authorize` it is host-supplied. |
| **RFC 7662** — Token Introspection | `POST /oauth/introspect` | **Partial** | Access tokens only — refresh tokens are opaque and **not** introspectable. Caller must authenticate as a **confidential** client, and may only introspect **its own** tokens, so a separate resource server cannot introspect. `token_type_hint` is ignored. |
| **RFC 7009** — Token Revocation | `POST /oauth/revoke` | **Partial** | Access tokens (by `jti`) and refresh tokens (revoking the whole family). **Confidential clients only** — a public client cannot revoke its own token, which §2.1 expects. `token_type_hint` is ignored. |
| **RFC 8414** — Authorization Server Metadata | `/.well-known/oauth-authorization-server` | **Full** | Same document as OIDC discovery. `authorization_endpoint` is **omitted** unless you configure where your app serves it — §2 permits omission, and advertising a route the package does not serve would be worse. |
| **RFC 9728** — Protected Resource Metadata | `/.well-known/oauth-protected-resource` | **Full** | |
| **RFC 8628** — Device Authorization Grant | `POST /oauth/device_authorization` | **Partial** | Full state machine: `user_code` on an unambiguous alphabet, hashed `device_code`, 600 s TTL, and the complete polling vocabulary (`authorization_pending`, `slow_down`, `access_denied`, `expired_token`). The **user-facing verification page** at `verification_uri` is **host-supplied** — the package registers no route for it. |
| **RFC 9126** — Pushed Authorization Requests | `POST /oauth/par` | **Partial** | Client-authenticated; single-use, row-locked, 90-second `request_uri`. **Consumption happens at `/authorize`, so it is host-supplied**, and `require_pushed_authorization_requests` is *advertised* from config but **enforced by your app, not by this package**. Setting `CBOX_ID_REQUIRE_PAR=true` alone changes only the discovery document. |
| **RFC 8693** — Token Exchange | `urn:ietf:params:oauth:grant-type:token-exchange` | **Partial** | Access-token→access-token only, down-scope-only, with `resource` re-audiencing and DPoP continuity. **No delegation or impersonation**: `actor_token`, `may_act` and the `act` claim are deliberately absent, as are the `id_token` and `saml2` token types. |
| **RFC 9449** — DPoP | Sender-constrained tokens | **Partial** | Proof validated for `typ`/`alg`/signature/`htm`/`htu`/`iat`/`ath`, with a database-backed single-use `jti` replay guard; `cnf.jkt` bound into access and refresh tokens and checked on rotation and exchange. **No DPoP nonce** (§8–9): no `DPoP-Nonce` header, no `use_dpop_nonce`. DPoP is **opt-in per token** — there is no switch to *require* sender-constrained tokens, so a client that omits the header simply gets a Bearer token. |
| **RFC 8707** — Resource Indicators | `resource` binds the access token's `aud` | **Partial** | **Single-valued only** — §2 permits repeating `resource`, and a second value is dropped. Not advertised in metadata (there is no registered metadata key), so this is under-advertised rather than over-advertised. |
| **RFC 7591** — Dynamic Client Registration | `POST /oauth/register` | **Partial** | Three modes (`disabled` / `protected` / `open`), advertised only when enabled. Redirect-URI rules include RFC 8252 private-use schemes and loopback. **A DCR client cannot register `private_key_jwt`** — the registrar's auth-method allow-list is `none` / `client_secret_basic` / `client_secret_post` and it ingests no `jwks`/`jwks_uri`. |
| **RFC 7592** — DCR Management Protocol | `GET`/`PUT`/`DELETE /oauth/register/{client}` | **Partial** | Registration access token compared in constant time. The returned document reports `token_endpoint_auth_method` as `client_secret_basic` for every confidential client, including one registered for `client_secret_post` or `private_key_jwt`. |
| **RFC 9207** — Authorization Server Issuer Identification | `iss` on the authorization response | **Host-supplied** | The package **advertises** `authorization_response_iss_parameter_supported` whenever you configure an `authorization_endpoint`, but it emits no authorization response and therefore appends no `iss`. If you serve your own `/authorize`, you must append it or the advertisement is a lie to mix-up-hardened clients. |
| **RFC 7523 §3** — JWT client authentication | `private_key_jwt` | **Full** | `RS256`/`ES256`/`EdDSA`; `iss == sub == client_id`; audience must be the issuer or the token endpoint; `exp` mandatory and capped at 300 s; single-use `jti`. |
| **RFC 7523 §2.1** — JWT bearer *authorization* grant | `urn:ietf:params:oauth:grant-type:jwt-bearer` | **No** | Not a supported grant. Do not confuse with §3 above, which is. |
| **RFC 8705** — Mutual-TLS client auth & certificate-bound tokens | `tls_client_auth`, `cnf.x5t#S256` | **No** | Not implemented, and correctly not advertised. |
| **RFC 9101** — JWT-Secured Authorization Request (JAR) | `request` / `request_uri` objects | **No** | `request_parameter_supported` and `request_uri_parameter_supported` are both advertised `false`. |
| **JARM** — JWT-secured authorization response mode | `response_mode=jwt` | **No** | `response_modes_supported` is `["query"]`. |
| **RFC 9470** — Step Up Authentication Challenge | `insufficient_user_authentication` challenge | **No** | Not implemented. The package supplies the *signals* a step-up decision needs — `auth_time`, `amr`, `acr` on the id_token — but issues no challenge and enforces no freshness. |
| **RFC 9700** — Best Current Practice for OAuth 2.0 Security | Refresh-token rotation with reuse detection; PKCE for public clients | **Full** | Single-use rotation inside a family, with a 10-second grace window that returns the *same* successor rather than minting siblings. A genuinely replayed token revokes the whole family. Refresh tokens are issued only when `offline_access` was granted. |

### Client authentication

| Method | Grade |
|---|---|
| `client_secret_basic`, `client_secret_post`, `none` | **Full** |
| `private_key_jwt` (RFC 7523 §3) | **Full** — but not reachable through Dynamic Client Registration; register such clients programmatically. |
| `client_secret_jwt` | **No** — no MAC algorithms are accepted for client assertions. Not advertised. |
| `tls_client_auth` / `self_signed_tls_client_auth` (RFC 8705) | **No** — not advertised. |

Client secrets are 256-bit and stored as a bare SHA-256 digest, not under a password KDF.
That is defensible for high-entropy machine credentials, and it is stated here rather than
left for you to discover.

## OpenID Connect

| Spec | What it covers | Grade | Notes |
|---|---|---|---|
| **OIDC Core 1.0** — id_token | `sub`, `iss`, `aud`, `iat`, `exp`, `nonce`, `at_hash`, `auth_time`, `acr`, `amr`, `org`, `org_name` | **Partial** | `response_type=code` only — no implicit, no hybrid. `response_mode=query` only — no `fragment`, no `form_post`. The `claims` request parameter is not supported (advertised `false`). id_tokens are **signed with RS256 only**, and `id_token_signing_alg_values_supported` advertises exactly that — discovery and issuance read the same constant, so the two cannot disagree. |
| **OIDC Core 1.0** — §12.2 refreshed id_token | `id_token` on `grant_type=refresh_token` | **Full** | The refresh response carries a new id_token whenever the grant has a user behind it. `iss`/`sub`/`aud` match the original, `iat` and `at_hash` describe the new tokens, and `auth_time`/`amr`/`acr` still describe the ORIGINAL login — the rotation family records them. No `nonce`: a refresh is not an authentication request, and echoing one would defeat the relying party's replay check. A `client_credentials` family gets none, having no subject to assert. |
| **OIDC Core 1.0** — UserInfo | `GET`/`POST /oauth/userinfo` | **Full** | Requires the `openid` scope, audience-restricted, DPoP-aware. |
| **OIDC Core 1.0** — `acr` / `acr_values` | Authentication context | **Partial / Host-supplied** | The package defines the vocabulary (`urn:cbox-id:aal1`, `urn:cbox-id:aal2` — **vendor URNs, not standard assurance-level identifiers**), advertises it, and stamps the resulting `acr` on the id_token. **Gating a request on `acr_values` happens at `/authorize` and is host-supplied**; nothing in `src/` refuses a request for an unmet class. |
| **OIDC Core 1.0** — `max_age` / `prompt` | Re-authentication | **Host-supplied** | `auth_time` is recorded on the session and stamped on the id_token so your app can decide. The package never returns `login_required` — that string does not appear in `src/`. |
| **OIDC Discovery 1.0** | `/.well-known/openid-configuration` | **Full** | Every advertised algorithm list is read from the constant the issuing or verifying code enforces — id_token signing, request-object signing and client-assertion signing all — so discovery cannot promise an algorithm the server would then refuse. |
| **OIDC RP-Initiated Logout 1.0** | `end_session_endpoint` | **Full** | Verified `id_token_hint`, exact-match `post_logout_redirect_uri` allow-list, `state` round-trip, `client_id`/hint audience agreement. |
| **OIDC Front-Channel Logout 1.0** | `frontchannel_logout_uri` | **No** | |
| **OIDC Back-Channel Logout 1.0** | Logout token, `sid` claim | **No** | |
| **OIDC Session Management 1.0** | `check_session_iframe` | **No** | |
| **OIDC CIBA** — Client-Initiated Backchannel Authentication | `POST /oauth/backchannel_authentication` | **Partial** | **Poll mode only** (`ping` and `push` are absent, and honestly advertised as absent). `login_hint` only — no `id_token_hint`, no `login_hint_token`, no signed CIBA request object. Supports `binding_message`, `nonce`, `requested_expiry` under a server ceiling, and the `slow_down` / `authorization_pending` / `expired_token` vocabulary. **The user notification and approval UI is host-supplied**; the package emits `oauth.backchannel_authentication_requested`. |
| **Pairwise subject identifiers** | `subject_types_supported` | **No** | `public` only; `sub` is the subject id. |

## Tokens, keys and JOSE

| Spec | What it covers | Grade | Notes |
|---|---|---|---|
| **RFC 7519 / RFC 9068** | JWT access tokens, `typ: at+jwt` | **Full** | `aud` always present, falling back to the issuer per RFC 9068 §2.2. `jti` recorded so a token can be revoked. Authorization codes and refresh tokens are opaque and SHA-256-hashed at rest. |
| **RFC 7515 / 7518** — JWS, JWA | Signing | **Partial** | A closed enum of `RS256`, `ES256`, `EdDSA`. No `none`, no HMAC — algorithm confusion is excluded at the type level rather than by a runtime check. |
| **RFC 7517** — JWK / JWK Set | `/.well-known/jwks.json` | **Full** | RSA, EC P-256 and OKP Ed25519 keys published with `kid`; Active and Rotating keys both published so rotation has an overlap window. |
| **RFC 8037** — Ed25519 in JOSE | `EdDSA` | **Full** | `at_hash` correctly derives from the id_token's own signing algorithm (SHA-512 for Ed25519), not a fixed SHA-256. |
| **RFC 8725** — JWT Best Current Practices | Algorithm pinning | **Full** | Verification requires a caller-supplied allow-list, and each key is bound to its own algorithm, so the token header's `alg` never selects the key. |
| **RFC 7516** — JWE | Encrypted tokens | **No** | No encrypted id_tokens, no encrypted UserInfo responses. |

> **Resolved.** `id_token_signing_alg_values_supported` used to be derived from the keys an
> environment held while id_tokens were always signed **RS256** — so an environment holding
> only ES256 or EdDSA advertised an algorithm it never signed with, and a conformant client
> that pinned what discovery told it broke on the first token. It now reads
> `TokenController::ID_TOKEN_ALG`, the constant issuance uses, and a test holds the two
> together. The DPoP and client-assertion algorithm lists read their validators' constants
> for the same reason: advertising is a statement about what this code accepts, so it reads
> the code.

## SCIM 2.0 (inbound provisioning server)

| Spec | What it covers | Grade | Notes |
|---|---|---|---|
| **RFC 7642** — Definitions, Overview, Concepts and Requirements | Informational | **n/a** | Non-normative; nothing to implement. |
| **RFC 7643** — Core Schema | `User`, `Group`, Enterprise User extension | **Partial** | All schema URNs are genuine. The `User` attribute set is a subset: `userName`, `externalId`, `name.*`, `displayName`, `emails`, `active`, plus the six Enterprise User attributes. `phoneNumbers`, `addresses`, `photos`, `roles`, `entitlements`, `title`, `locale` and friends are *accepted and discarded* — and `/Schemas` honestly declares them `returned: "never"` rather than promising a round-trip that never happens. |
| **RFC 7644 §3.2–3.6** — CRUD | `GET`/`POST`/`PUT`/`PATCH`/`DELETE` on `/Users` and `/Groups` | **Full** | |
| **RFC 7644 §3.5.2** — PATCH | `add` / `remove` / `replace` | **Partial** | `add` and `replace` are treated identically — there is no multi-valued append. On `/Users` a value filter in a path (`emails[type eq "work"].value`) is **stripped, not evaluated**. On `/Groups`, `members[value eq "…"]` *is* honoured, but only that exact shape. `remove` without a path is refused with `noTarget`, as §3.5.2.2 requires. |
| **RFC 7644 §3.4.2.2** — Filtering | Filter grammar | **Partial** | `/Users`: `eq`, `ne`, `pr` on all types; `co`, `sw`, `ew` on text; `gt`, `ge`, `lt`, `le` on timestamps only; a single top-level `and` **or** `or`. **No** parentheses, **no** `not`, **no** mixing `and` with `or`, **no** `attr[...]` value paths. Filterable attributes are a closed allow-list — anything else is refused as `invalidFilter` rather than silently returning nothing. `/Groups` is narrower still: `displayName eq` and `externalId eq` only. |
| **RFC 7644 §3.4.2.4** — Pagination | `startIndex`, `count` | **Full** | Page size capped at 200, which is what `filter.maxResults` advertises. |
| **RFC 7644 §3.9** — Attribute selection | `attributes`, `excludedAttributes` | **Partial** | Honoured only for `Group.members`; **ignored on `/Users`**. |
| **RFC 7644 §3.4.2.3** — Sorting | `sortBy`, `sortOrder` | **No** | Advertised as unsupported, and **silently ignored** rather than refused. Results are ordered by primary key. |
| **RFC 7644 §3.14** — Versioning / ETags | `ETag`, `If-Match` | **No** | Advertised as unsupported. |
| **RFC 7644 §3.7** — Bulk | `/Bulk` | **No** | Advertised as unsupported. |
| **RFC 7644 §3.4.3** — Search | `POST /.search` | **No** | No metadata field exists to advertise it. |
| **RFC 7644 §3.11** — `/Me` | Self-service | **No** | |
| **RFC 7644 §3.12** — Errors | SCIM Error schema, `scimType` | **Full** | Enforced at the base controller, and framework-rendered errors (including a 429) are re-framed into the SCIM envelope rather than leaking `application/json`. Emits `invalidFilter`, `invalidValue`, `invalidSyntax`, `noTarget`, `invalidPath`, `uniqueness`, `mutability`. |
| **RFC 7644 §4** — Discovery | `ServiceProviderConfig`, `ResourceTypes`, `Schemas` | **Partial** | Collections only — there are no `/ResourceTypes/{id}` or `/Schemas/{urn}` routes. Every capability flag matches the implementation. Note the discovery endpoints sit **behind** bearer authentication, so a connector that probes them anonymously gets a 401. |

`/Me`, `/Bulk` and `/.search` are not registered as routes at all, so a request to them
returns Laravel's plain-JSON 404 rather than a SCIM Error envelope.

## SAML 2.0

The OASIS specifications: *Assertions and Protocols* (`saml-core-2.0-os`), *Bindings*
(`saml-bindings-2.0-os`), *Metadata* (`saml-metadata-2.0-os`) and *Profiles*
(`saml-profiles-2.0-os`), with W3C *XML Signature Syntax and Processing* and *Exclusive
XML Canonicalization*. Signatures are produced and verified by `robrichards/xmlseclibs`
and `onelogin/php-saml` — never hand-rolled.

### As an identity provider (downstream SPs federate to you)

| Capability | Grade | Notes |
|---|---|---|
| Web Browser SSO profile — HTTP-Redirect and HTTP-POST request bindings | **Full** | Both advertised, both verified. **HTTP-Artifact: No.** |
| Signed assertion and signed `Response` | **Full** | RSA-SHA256, SHA-256 digest, exclusive C14N. The signing key must be RSA; a non-RSA active key is refused rather than downgraded. |
| Signed `AuthnRequest` verification | **Full** | Per-SP, both bindings, with `SignatureMethod` and `DigestMethod` pinned to RSA-SHA256/SHA-256 so an SHA-1 signature is refused. |
| XML Signature Wrapping defence | **Full** | Exactly one `ds:Signature` as a direct child of the message root, exactly one `Reference`, the `Reference` URI bound to the root id, and verification XPath-pinned to the element the parser actually read. Regression-tested with a real wrapping attack. |
| NameID formats | **Full** | `emailAddress` and `unspecified` (the SAML 1.1 URNs that SAML 2.0 §8.3 reuses), `persistent`, `transient`. The SAML 1.0 spelling of `unspecified` is accepted on input and normalised, never published. Advertised formats are the *intersection* of what the registered SPs can be answered under, computed by the same predicate that enforces it. |
| IdP metadata | **Partial** | Derived from the registrations rather than hardcoded, with one `KeyDescriptor` per currently-trusted key. **Not signed**, and carries no `validUntil`/`cacheDuration` — some SP tooling wants both. |
| Single Logout, SP-initiated | **Full** | Signature required and verified on the inbound `LogoutRequest`, both bindings; a **signed** `LogoutResponse` is returned; 300-second freshness window and single-use message ids. |
| Single Logout, IdP-initiated fan-out to other SPs | **No** | Global single logout is not implemented. |
| IdP-initiated (unsolicited) SSO | **No** | Every issued `Response` carries `InResponseTo`. |
| Encrypted assertions (outbound) | **No** | Issued assertions are signed, not encrypted. Correctly not advertised — the metadata publishes a signing `KeyDescriptor` only. |
| `AuthnContext` in the assertion | **Full** | Derived from the session's `amr` — the same list the OIDC side derives `acr` from, so the two protocols cannot describe one sign-in differently. A password yields `PasswordProtectedTransport` (not bare `Password`, which asserts no transport protection); a passkey yields `unspecified`, because SAML 2.0's class list predates WebAuthn and `Smartcard`/`SoftwarePKI` would both be untrue. A caller that supplies no `amr` gets `unspecified` — vague rather than wrong. The core classes cannot express "and also a second factor"; an SP that needs that should read a mapped attribute, not a class reference that cannot carry it. |

### As a relying party (you federate to a customer's IdP)

| Capability | Grade | Notes |
|---|---|---|
| SP-initiated login (`AuthnRequest`, HTTP-Redirect) | **Partial** | Requests are **not signed**, and the SP metadata honestly advertises `AuthnRequestsSigned="false"`. An IdP that requires signed requests is not supported. |
| ACS processing | **Full** | `wantAssertionsSigned`, strict mode, XXE-safe parsing, audience / recipient / `InResponseTo` / `NotBefore` / `NotOnOrAfter` validation, RSA-SHA256 pinned on every signature in the document. |
| Assertion replay protection | **Full** | Assertion ids are single-use, enforced by a unique index, with the TTL taken from `NotOnOrAfter`. |
| Single Logout | **Partial** | An upstream IdP's `LogoutRequest` is signature-verified and revokes the subject's sessions, returning a `LogoutResponse`. The SP never *initiates* a `LogoutRequest`, so the advertised endpoint is receive-only. |
| Encrypted assertions (inbound) | **Partial** | Decryption works once key material is configured — but the SP metadata publishes **no** `use="encryption"` `KeyDescriptor`, so an IdP importing that metadata has no certificate to encrypt to. |
| IdP-initiated (unsolicited) SSO | **Full, opt-in** | Off by default; a `Response` without `InResponseTo` is refused unless the connection explicitly enables it, because it is a login-CSRF sink. |
| Attribute mapping and just-in-time provisioning | **Full** | A new federated identity is never merged into an existing account by email — that path is refused so linking stays explicit. A deactivated account is refused a fresh session. |

### Inbound OIDC federation

| Capability | Grade | Notes |
|---|---|---|
| `id_token` verification | **Partial** | **RS256 only** — a token advertising any other `alg` is refused. `iss`, `aud` and `azp` all validated (closing shared-IdP cross-RP replay), plus `exp`/`nbf`/`iat`. |
| JWKS fetch, cache and rotation | **Full** | SSRF-gated and DNS-pinned, 1-hour cache, one forced refetch on a `kid` miss, rate-limited so a rotation cannot amplify into a fetch flood. |
| Issuer discovery | **Full** | `/.well-known/openid-configuration`, with the issuer-match check of OIDC Discovery §4.3 failing closed. |
| `state` and `nonce` | **Full** | 128-bit, single-use, compared in constant time. Kept in the session AND in a per-connection `SameSite=None; Secure; HttpOnly` cookie, because a `form_post` answer is a cross-site POST that a `SameSite=Lax` session cookie is not sent with. |
| `response_mode=form_post` | **Full** | Sent when the catalogue entry declares it, and the redirect URI accepts POST as well as GET. Apple switches to `form_post` by itself once any scope beyond `openid` is requested, so a GET-only relying party cannot complete a sign-in with it at all. |
| Client authentication by signed assertion (RFC 7523 §2.2, `private_key_jwt` in shape) | **Partial** | Used where the provider issues no secret: an ES256 assertion is minted per token request from the administrator's registered signing key, `aud` the provider, cached for an hour. This is what Sign in with Apple requires. The parameter is still `client_secret` — the JWT is sent as its value, which is what Apple specifies, rather than as `client_assertion` with `client_assertion_type`. A provider wanting the RFC's own parameter names is not yet supported. |
| **PKCE on the outbound leg** | **No** | This package requires PKCE of *its* clients but does not use it as a client. No `code_challenge` is sent and no `code_verifier` is returned. |
| UserInfo | **No** | The endpoint is discovered but never called; claims come from the `id_token`. |

## Multi-factor and credentials

| Spec | What it covers | Grade | Notes |
|---|---|---|---|
| **RFC 6238** — TOTP | Time-based one-time passwords | **Partial** | Verified against the RFC 6238 test vectors in the suite. **HMAC-SHA1, 6 digits, 30-second period, ±1 step — all fixed, none configurable.** Secrets sealed at rest; replay blocked by a monotonic last-used step. |
| **RFC 4226** — HOTP | Counter-based one-time passwords | **No** | The truncation core exists as a private building block of TOTP; there is no counter-based factor, no public API and no resync. |
| **W3C Web Authentication** / FIDO2 | Passkeys | **Partial** | Real registration and assertion verification against genuine software-authenticator vectors, with user-verification enforced and sign-counter clone detection. **ES256 (P-256) and RS256 only.** Attestation: `none` and *self-attested* `packed` only — `x5c` certificate chains are **refused**, and there is no FIDO Metadata Service or AAGUID allow-listing. Unknown formats are refused, so this fails safe. **Inert until `CBOX_ID_WEBAUTHN_RP_ID` and `CBOX_ID_WEBAUTHN_ORIGIN` are set** — the default binding throws. Challenge issuance and storage are host-supplied. |
| Recovery / backup codes | Single-use, regenerable | **Full** | Ten 64-bit codes, SHA-256 at rest, claimed by conditional update. |
| Password hashing | bcrypt / argon2i / argon2id | **Full** | Via the framework hasher; rehash-on-login when parameters change. |
| Foreign hash import | Migrating off another provider | **Partial** | A **deny-by-default** verifier registry that ships **only** the native bcrypt/argon2 verifier. phpass, MD5, SHA-1, PBKDF2, scrypt and LDAP digests are **not** included — an unrecognised hash is refused, never silently passed, and you add a format by binding your own verifier. |
| Password policy | Length, reuse history, expiry, lockout, MFA and SSO mandates | **Full** | Environment sets a floor, an organization may only tighten it. Minimum length defaults to 12. |
| Breached-password screening | HIBP k-anonymity or equivalent | **Contract only** | `BreachedPasswordCheck` ships, and the bound default `NeverBreachedCheck` **always answers "not breached"**. Note the policy flag `requireBreachCheck` defaults to *true*, so the policy asks for a check that the shipped implementation cannot perform. Bind your own, or use the deployable app. |
| Password complexity classes | Upper/lower/digit/symbol rules | **No** | Not modelled. |

## Model Context Protocol (MCP)

The MCP authorization model expects a standards-compliant OAuth 2.0 authorization
server. The five pieces it requires:

| MCP requirement | Backed by | Grade |
|---|---|---|
| Authorization Server Metadata | RFC 8414 | **Full** |
| Protected Resource Metadata | RFC 9728 | **Full** |
| Dynamic Client Registration | RFC 7591 | **Full** (off by default — enable a mode) |
| PKCE | RFC 7636 | **Full** (`S256`) |
| Resource / audience binding | RFC 8707 | **Partial** (single-valued) |

An MCP client can discover the server, self-register, run authorization-code + PKCE, and
receive an access token audience-bound to the MCP server it intends to call — **once your
app serves `/authorize`** and you have set `cbox-id.oauth.authorization_endpoint_path`.

## Refresh tokens

Refresh tokens are issued only when the client is granted `offline_access`. Every rotation
is single-use: presenting a refresh token consumes it and mints a successor in the same
*family*. Presenting an already-consumed token outside the 10-second grace window is
treated as theft — the entire family is revoked, forcing re-authentication.

## Where to go next

- [FAPI hardening](fapi.md) — which parts of the FAPI 2.0 baseline are switchable today,
  and which are structurally out of reach.
- [Feature support matrix](../capabilities/feature-support.md) — everything that is not a
  wire protocol.
- [Compliance mapping](compliance.md) — how these controls line up with SOC 2, ISO 27001,
  NIS2, GDPR, HIPAA and PCI-DSS, and what stays yours.
