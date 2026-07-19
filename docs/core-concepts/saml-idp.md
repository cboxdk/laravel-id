---
title: SAML Identity Provider
description: Act as the SAML 2.0 IdP that downstream SPs (Salesforce, Workday, AWS) federate to — signed assertions, ACS/audience pinning, RSA-SHA256
weight: 8
---

# SAML 2.0 Identity Provider

Cbox ID can act as a SAML 2.0 **Identity Provider (IdP)**: the authority that
downstream **service providers (SPs)** — Salesforce, Workday, AWS, or any
SAML-conformant application — federate to for single sign-on. This is the mirror
image of the [federation](../core-concepts/architecture.md) side, where the
platform is the *relying party* consuming an external IdP.

The module lives in `src/SamlIdp/` and is contracts-first: the host app drives the
flow (it owns "who is logged in"), and the package supplies the protocol layer —
request parsing, assertion minting, signing, and metadata.

## Mental model

```
SP (e.g. Salesforce)                     Cbox ID (IdP)
────────────────────                     ─────────────
1. builds an AuthnRequest  ──redirect──▶  parseAuthnRequest()
                                           · issuer is a registered, active SP?
                                           · ACS matches the registration?
                                           · signature required & valid?
2. host authenticates the subject  ◀────  (hand-off — host's job)
                                    ────▶  issueResponse(subject, attributes)
                                           · signed Assertion (+ signed Response)
3. consumes the assertion  ◀──POST────    auto-submit form → SP's registered ACS
```

The honest-crypto stance is non-negotiable: the XML digital signature is produced
by the vetted `robrichards/xmlseclibs` (via `onelogin/php-saml`'s `addSign`), never
hand-rolled. The package builds the SAML protocol XML; the library does the
canonicalization and RSA math.

## Registering a service provider

An SP is an environment-owned record (`saml_service_providers`). It is the single
source of truth the IdP consults before it will issue anything:

```php
use Cbox\Id\SamlIdp\Contracts\ServiceProviders;
use Cbox\Id\SamlIdp\ValueObjects\NewServiceProvider;
use Cbox\Id\SamlIdp\Enums\NameIdFormat;

app(ServiceProviders::class)->register(new NewServiceProvider(
    entityId: 'https://saml.salesforce.com',
    acsUrl: 'https://login.salesforce.com/?saml=...',   // the ONLY place assertions are sent
    nameIdFormat: NameIdFormat::EmailAddress,
    nameIdAttribute: 'email',                            // subject field → NameID
    attributeMappings: [                                 // SAML attribute → subject field
        'email' => 'email',
        'displayName' => 'name',
    ],
    certificate: $spSigningCertPem,                      // to verify signed AuthnRequests
    wantAuthnRequestsSigned: true,
));
```

`acs_url` is matched **exactly** — no wildcards, and a request-supplied
`AssertionConsumerServiceURL` that differs is refused. That exact match is the
open-redirect / assertion-to-attacker defense.

## Endpoints

Registered by the `Api` layer behind `ResolveEnvironment` + throttling:

| Route | Purpose |
| --- | --- |
| `GET /sso/saml/idp/metadata` | IdP metadata: EntityID, SSO/SLO endpoints, signing certificate (public). |
| `GET\|POST /sso/saml/idp/sso` | SingleSignOnService: parse+validate the AuthnRequest; hand off to the host to authenticate; resume to mint + auto-POST. |
| `GET\|POST /sso/saml/idp/slo` | SingleLogoutService: verifies a signed SP `LogoutRequest`, revokes the subject's local sessions, and returns a signed `LogoutResponse`. |

The controllers are thin. The interactive "is a user logged in / log them in" step
is the host's responsibility — exactly as the OAuth `/authorize` endpoint is. When
no subject is authenticated, the SSO endpoint redirects to
`config('cbox-id.saml_idp.login_url')` (carrying `return_to`) so the host can
authenticate and re-dispatch, or returns `401` when no login URL is configured.

### CSRF and the HTTP-POST binding

The SSO route lives in the host's `web` middleware group. With the **HTTP-POST
binding**, an SP delivers the `AuthnRequest` as a cross-site form POST from the SP's
own origin — that request carries **no Laravel CSRF token**, so with CSRF protection
enabled the POST is rejected (`419`) before it ever reaches the IdP. The host app
must therefore **exempt the SSO endpoint from CSRF verification**:

```php
// app/Http/Middleware/VerifyCsrfToken.php  (host app)
protected $except = [
    'sso/saml/idp/sso',   // SAML HTTP-POST binding: cross-site SP POST, no CSRF token
];
```

This is **fail-closed**: forgetting the exemption breaks the POST binding (SPs get a
`419`), it does not weaken security. The endpoint's own trust checks are unchanged
and do not rely on CSRF — the `AuthnRequest` is authenticated by its **XML
signature** (when the SP requires signing) and every issued assertion is pinned to
the SP's registered ACS and audience regardless of who submitted the request. The
HTTP-Redirect binding uses a GET and is unaffected. If you only ever use the
redirect binding, the exemption is unnecessary.

A host that wants full control over attribute release ignores the controller and
drives the contract directly:

```php
$idp = app(\Cbox\Id\SamlIdp\Contracts\SamlIdentityProvider::class);

$request  = $idp->parseAuthnRequest($samlRequest, $relayState, $signature, $sigAlg, $fromRedirect);
// ... host authenticates the subject ...
$response = $idp->issueResponse($request, $subjectId, ['email' => '...', 'name' => '...']);

return response($response->toPostForm());   // self-submitting POST form to the ACS
```

## How the assertion is signed

`issueResponse()` builds the Response/Assertion XML with DOM (never string
concatenation, so every value is escaped) and then:

1. **Signs the Assertion** with `xmlseclibs` — enveloped signature, **exclusive
   C14N** (`http://www.w3.org/2001/10/xml-exc-c14n#`), **RSA-SHA256**
   (`…xmldsig-more#rsa-sha256`), **SHA-256** digest — inserting the `ds:Signature`
   right after `saml:Issuer` (schema-correct placement). The signing certificate is
   embedded in `KeyInfo`.
2. **Signs the enclosing Response** over the already-signed Assertion via
   `onelogin/php-saml`'s `Utils::addSign` (same primitives). Signing order is
   Assertion-first so neither signature invalidates the other.

The assertion carries: a bearer `SubjectConfirmation` (Recipient = the registered
ACS, `InResponseTo` = the request id, short `NotOnOrAfter`), `Conditions` with a
~5-minute window and an `AudienceRestriction` pinned to the SP EntityID, and an
`AuthnStatement`. SHA-1 is never emitted.

### One identity, one key

The IdP signs with the **platform's active RSA signing key** (`KeyManager::activeSigningKey`,
RS256), the same key behind JWKS/OIDC — there is no second key store. Its private
half is opened from the sealed store only in memory at signing time. The public
half is wrapped in a self-signed X.509 certificate, generated once and persisted
per `kid` (`saml_idp_certificates`), and published in metadata for SPs to pin. If
the active key is ever non-RSA the IdP refuses to sign rather than downgrade.

## Deny-by-default matrix

| Condition | Result |
| --- | --- |
| Issuer is not a registered SP (this environment) | refused (`UnknownServiceProvider`) |
| SP status is not `active` | refused |
| Request `AssertionConsumerServiceURL` ≠ registered `acs_url` | refused (`InvalidAuthnRequest`) |
| SP requires signed requests, request unsigned | refused |
| Request `SigAlg` is SHA-1 or unknown | refused (algorithm pinned to RSA-SHA256; POST binding pins the embedded `SignatureMethod`/`DigestMethod` too) |
| Request signature does not verify against the SP cert | refused |
| POST-binding signature does not cover the request root (XML Signature Wrapping) | refused — the `ds:Signature` must be an enveloped signature that is a direct child of the root, its `Reference` must cover that root, and verification is pinned to it |
| Malformed XML, or a DOCTYPE/ENTITY (XXE) payload | refused (parsed via the XXE-safe loader) |

The assertion is always addressed to the **registered** ACS and audience-restricted
to the **registered** EntityID, both re-pinned at issuance time — never copied from
the request.

## Proven against a real verifier

The test suite does not assert against a mock. It registers an SP, issues a
Response, and validates it with **`onelogin/php-saml` acting as the SP** (a real,
independent SAML verifier): the signature verifies, and audience, recipient,
`InResponseTo` and conditions all check out. A companion test flips a byte in the
signed assertion and asserts the same verifier **rejects** it. Signed-request
handling is exercised with a real RSA keypair on **both bindings** (accepted when
correct; refused when unsigned, SHA-1, or tampered) — including an **XML Signature
Wrapping** regression test that presents a valid signature over a decoy element with
attacker-controlled content in the processed root and asserts it is refused.

## Scope & limitations (honest)

Implemented: signed assertions and signed responses, ACS/audience pinning,
RSA-SHA256 with exclusive C14N, XXE-safe request parsing, signed-AuthnRequest
verification (redirect and POST bindings), IdP metadata.

**Not yet implemented** — do not assume these:

- **Assertion encryption** (`EncryptedAssertion`). Assertions are signed, not
  encrypted. SPs that mandate encrypted assertions are not yet supported.
- **Front-channel logout fan-out.** SP-initiated Single Logout is supported: a
  signed `LogoutRequest` is verified against the SP's certificate, the local session
  is revoked, and a signed `LogoutResponse` is returned to the SP's SLO endpoint. The
  IdP does **not** yet fan out `LogoutRequest`s to *other* federated SPs to end their
  sessions in the same browser (global single logout).
- **IdP-initiated (unsolicited) SSO.** The issued Response always carries
  `InResponseTo`; the SP-initiated flow is the supported path.
