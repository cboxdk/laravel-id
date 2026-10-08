---
title: Sign-in provider catalogue
description: The fifteen social and workforce providers ProviderCatalog knows — issuers, endpoints, scopes, claim mapping — and how an entry becomes a working sign-in
weight: 19
---

# Sign-in provider catalogue

`Cbox\Id\Federation\ProviderCatalog` lists the providers a person can sign in **with**:
Google, Microsoft Entra ID, Okta, Auth0, Keycloak, GitLab, Slack, GitHub, Discord,
Apple, Facebook, LinkedIn, Bitbucket, Xero and Intuit. Each entry is a
`ProviderTemplate` holding everything that is the same for every customer — issuer or
endpoints, scopes, where the identity sits in the response, setup steps in the
provider's own vocabulary, and a documentation link. The only things an administrator
supplies are their client ID and secret, plus any per-installation parameter (an Entra
directory ID, an Okta domain).

This is the list that `ProviderCatalog::withCapability(ProviderCapability::Login)`
returns, so it is what a sign-in page renders as buttons. Enterprise identity providers
that sign *their* people in to *you* over SAML or OIDC are a different list — see
[Enterprise SSO setup guides](../cookbook/enterprise-sso-setup-guides.md).

## Providers

| Key | Provider | Protocol | Notes |
|---|---|---|---|
| `google` | Google | OIDC | Also a directory (Admin SDK pull). |
| `microsoft` | Microsoft Entra ID | OIDC | Issuer names the directory; also a directory (Graph pull). |
| `okta` | Okta | OIDC | Issuer from the org domain. |
| `auth0` | Auth0 | OIDC | Issuer from the tenant domain. |
| `keycloak` | Keycloak | OIDC | Issuer from host and realm. |
| `gitlab` | GitLab | OIDC | gitlab.com or self-managed. |
| `slack` | Slack | OIDC | |
| `github` | GitHub | OAuth 2.0 | Subject is the numeric `id`; address from `/user/emails`. |
| `discord` | Discord | OAuth 2.0 | Subject is the snowflake `id`. |
| `apple` | Apple | OIDC | Minted ES256 client secret, `form_post`, name sent once. |
| `facebook` | Facebook | OAuth 2.0 | Email may be absent. |
| `linkedin` | LinkedIn | OIDC | Sign In with LinkedIn using OpenID Connect. |
| `bitbucket` | Bitbucket | OAuth 2.0 | Bitbucket Cloud OAuth consumer. |
| `xero` | Xero | OIDC | Sign In with Xero. |
| `intuit` | Intuit | OIDC | Sign In with Intuit (QuickBooks), production keys. |

The order is stable and new entries are appended, so a stored `provider` key and a
console's button order never move.

## From entry to sign-in

**OIDC.** The host resolves the issuer with `$template->issuerFor($values)` and runs
discovery against the template's own document:

```php
use Cbox\Id\Federation\OidcDiscovery;
use Cbox\Id\Federation\ProviderCatalog;

$template = ProviderCatalog::find('intuit');
$issuer = $template->issuerFor($values);

$discovered = app(OidcDiscovery::class)->fromIssuer($issuer, $template->discoveryUrl);

$config = [...$discovered->toConfig(), 'client_id' => $clientId, 'client_secret' => $secret];
```

Discovery refuses a document whose `issuer` differs from the one requested, wherever the
document was fetched from. `toConfig()` carries the endpoints, `jwks_uri`,
`userinfo_endpoint` and — only when it is not the default — the token endpoint
authentication method. The callback at `/sso/oidc/{connection}/callback` then exchanges
the code, verifies the `id_token` (RS256, issuer, audience, `azp`, nonce) and provisions
the principal.

**OAuth 2.0.** There is nothing to discover. `OAuth2Client` uses the template's fixed
endpoints, exchanges the code, fetches the profile, and reads the subject, name and
address through the template's `ProviderProfileMap`.

## How a client secret is presented

RFC 6749 §2.3.1 allows the secret in the request body (`client_secret_post`) or as HTTP
Basic credentials (`client_secret_basic`). `TokenEndpointAuthMethod` names both.

- **OIDC:** the body form, unless the provider's discovery document lists
  `token_endpoint_auth_methods_supported`, leaves `client_secret_post` out, and names
  `client_secret_basic`. A document that says nothing keeps the body form — LinkedIn
  publishes no list and accepts only the body. A connection carrying a signing key
  (Apple) always sends its minted assertion in the body.
- **OAuth 2.0:** the template's `tokenEndpointAuthMethod`, `ClientSecretPost` by default.
  Bitbucket uses `ClientSecretBasic`.

Only one method is ever used per request, as RFC 6749 §2.3 requires.

## The four providers added in 1.23

### LinkedIn

- Issuer `https://www.linkedin.com/oauth` — the value LinkedIn's discovery document
  publishes. Scopes `openid profile email`; the `id_token` carries `name`, `email` and
  `email_verified`.
- The app needs the **Sign In with LinkedIn using OpenID Connect** product (Products
  tab) before those scopes are granted. The redirect URI goes on the **Auth** tab.
- `sub` is pairwise: the same member has a different subject under each LinkedIn app.
  Replacing the app unlinks every account; rotate the secret instead.

### Bitbucket

- Authorization `https://bitbucket.org/site/oauth2/authorize`, token
  `https://bitbucket.org/site/oauth2/access_token` with HTTP Basic, profile
  `https://api.bitbucket.org/2.0/user`. Scopes `account email`, which must also be
  granted on the OAuth consumer — Bitbucket refuses a request asking for more.
- Subject `uuid`. Never `username` (deprecated) or `nickname` (not unique).
- The address comes from `https://api.bitbucket.org/2.0/user/emails`, a paginated
  `{"values": [{"email", "is_primary", "is_confirmed"}]}` envelope. Only the primary
  address is taken, and only when it is confirmed; it is then reported verified. An
  unconfirmed primary yields no address at all. `ProviderProfileMap` describes this with
  `emailListPath`, `emailEntryAddress`, `emailEntryPrimary` and `emailEntryVerified`.

### Xero

- Issuer `https://identity.xero.com`, scopes `openid profile email`. Linked by `sub`,
  which Xero documents as the unique identifier for the end user; its tokens also carry
  `xero_userid`, the id in Xero's own APIs.
- Xero sends no `email_verified`, so the address is stored unverified.

### Intuit

- Issuer `https://oauth.platform.intuit.com/op/v1`, scopes `openid email profile`.
  Discovery uses Intuit's documented document,
  `https://developer.api.intuit.com/.well-known/openid_configuration`
  (`ProviderTemplate::$discoveryUrl`).
- The `id_token` carries no address. With `profileFromUserInfo` set, the callback calls
  the UserInfo endpoint with the access token from the same exchange, after the token and
  nonce are verified. The UserInfo `sub` must equal the token's (OIDC Core §5.3.2) or the
  sign-in is refused. UserInfo fills only what the token left empty, and Intuit's
  camel-cased `emailVerified` is read from it.
- Production keys only. Intuit's sandbox document differs in its UserInfo host, and
  Development keys work only with sandbox companies; connect a sandbox as an ordinary
  hand-configured OIDC connection.

## When an address counts as verified

The same rule applies to every OIDC connection, whether the flag arrived in the
`id_token` or from UserInfo: the provider must say `true`, **and** the address must be
in a domain the connection's organization has verified (`OrganizationVouchedEmail`). An
organization can point a connection at an identity provider it controls, so a provider's
word alone cannot mark an address in someone else's domain verified. A connection owned
by the environment rather than an organization carries the provider's flag unless an
organization has verified the address's domain. For OAuth 2.0
providers the flag is read from where the profile map says the provider puts it, and
only an explicit `true` counts.

Nothing ever merges a federated identity into an existing account by email.

## Extension points

- `Contracts\OidcTokenExchange` — the code exchange that returns an `OidcTokenSet`
  (`idToken`, `accessToken`). The shipped `OidcClient` implements it alongside
  `OidcRelyingParty`. A host that binds its own relying party without it still signs
  people in; only UserInfo-backed providers lose their address.
- `Contracts\OidcUserInfo` — completes a principal from UserInfo for catalogue entries
  with `profileFromUserInfo`; a no-op for every other connection. Bound to
  `OidcUserInfoClient`.
