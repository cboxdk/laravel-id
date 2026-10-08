---
title: Enterprise SSO setup guides
description: Show an IT administrator exactly which of your values goes in which field of their identity provider, for twenty IdPs, with SCIM where the IdP supports it
weight: 46
---

# Enterprise SSO setup guides

When a customer connects their own identity provider, the hard part is not the protocol.
It is the administrator on their IdP's admin screen, holding your ACS URL and entity ID,
looking for fields called something else. `Cbox\Id\Federation\IdentityProviderGuides`
holds that mapping for twenty identity providers: which of **your** values goes into
which of **their** fields, by the label their screen prints, what they hand back, the
steps in their own vocabulary, and a link to the vendor's documentation.

These guides are for the inbound direction — the customer's IdP signing its people in to
you over SAML 2.0 or OpenID Connect, and pushing them to you over SCIM. Providers people
sign in **with** (Google, GitHub, LinkedIn…) are the
[sign-in provider catalogue](../core-concepts/sign-in-provider-catalogue.md), which is
what sign-in buttons are built from. The two lists are kept apart so that an enterprise
IdP never becomes a button.

## The guides

| Key | Identity provider | Protocol | SCIM push |
|---|---|---|---|
| `okta` | Okta | SAML | Yes |
| `entra` | Microsoft Entra ID | SAML | Yes |
| `google` | Google Workspace | SAML | No |
| `onelogin` | OneLogin | SAML | Yes (SCIM Provisioner with SAML connector) |
| `jumpcloud` | JumpCloud | SAML | Yes |
| `pingfederate` | PingFederate | SAML | Yes (SCIM Provisioner add-on) |
| `pingone` | PingOne | SAML | Yes |
| `adfs` | AD FS | SAML | No |
| `auth0` | Auth0 | SAML | No |
| `keycloak` | Keycloak | OIDC | No |
| `duo` | Duo | SAML | Yes |
| `cyberark` | CyberArk Identity | SAML | Yes |
| `shibboleth` | Shibboleth IdP | SAML | No |
| `oracle` | Oracle Cloud Infrastructure IAM | SAML | Yes |
| `sap` | SAP Cloud Identity Services | SAML | No |
| `salesforce` | Salesforce | SAML | No |
| `lastpass` | LastPass | SAML | No |
| `cloudflare` | Cloudflare Access | SAML | No |
| `saml` | Any SAML 2.0 IdP | SAML | — |
| `oidc` | Any OpenID Connect provider | OIDC | — |

"SCIM push" means the IdP can provision a custom application over SCIM 2.0 using a
bearer token. An IdP that only provisions a fixed list of catalogued apps (Google), that
is itself a SCIM server rather than a client (Keycloak), or whose SCIM target accepts
only Basic or client-credentials authentication (SAP) has no directory guide. For any
other SCIM 2.0 client, `IdentityProviderGuides::genericDirectory()` describes the two
values every client needs.

## Rendering a guide

Fill a `ServiceProviderValues` with the connection's values, then let each field pick
the one it asks for:

```php
use Cbox\Id\Federation\IdentityProviderGuides;
use Cbox\Id\Federation\ValueObjects\ServiceProviderValues;

$guide = IdentityProviderGuides::find('onelogin');

$values = new ServiceProviderValues(
    acsUrl: url("/sso/saml/{$connection->id}/acs"),
    entityId: $spEntityId,
    sloUrl: url("/sso/saml/{$connection->id}/slo"),
    spMetadataUrl: url("/sso/saml/{$connection->id}/metadata"),
    loginUrl: url("/sso/saml/{$connection->id}/login"),
);

foreach ($guide->fields as $field) {
    // $field->theirs   "ACS (Consumer) URL Validator" — never translate this
    // $field->location where on their screen, when the label alone is ambiguous
    // $field->optional true for e.g. a Single Logout URL
    $value = $field->valueFrom($values);
}

$guide->returns->kind;   // GuideReturnKind::Url — "Issuer URL"
$guide->setupSteps;      // English steps
$guide->documentationUrl;
```

Two values are derived for you: `SpValue::AcsUrlPattern` (the anchored, escaped regex
OneLogin's validator wants) from the ACS URL, and `SpValue::ScimHost` /
`SpValue::ScimBasePath` (Oracle asks for host and path separately) from the SCIM base
URL. `SpValue::ScimToken->isSecret()` tells a console which value to show once and mask.

`returns->kind` decides the next form: `Url` (a SAML metadata URL to fetch), `Xml` (a
file to upload), `UrlOrXml` (prefer the URL — it lets you pick up their certificate
rotation), or `Oidc` (issuer, client ID and client secret).

## Lists

```php
IdentityProviderGuides::all();                         // every guide, console order
IdentityProviderGuides::forProtocol(GuideProtocol::Saml);
IdentityProviderGuides::directories();                 // guides with a SCIM directory guide
IdentityProviderGuides::genericDirectory();
ProviderCatalog::enterpriseGuides();                   // the same list, from the catalogue
```

## Translating the console

Field labels (`theirs`, `location`, `returns->theirs`) are what the administrator looks
for on the IdP's screen, so they stay exactly as the vendor prints them in every
language. The steps are English. A host that translates its console keeps its own
translated step text keyed by the guide `key`, and reads everything else from here.

## How the labels were sourced

Every label was read on the vendor's own documentation, and `documentationUrl` is the
page that was read. A label that could not be confirmed there was left out rather than
guessed. Admin consoles change; if a label has moved, the vendor link on the guide is the
first place to check.
