---
title: Integrating an existing app
description: Adopt Cbox ID over an app that already has users/auth (incl. Laravel Passport), and unify auth across products
weight: 6
---

# Integrating an existing app

You do **not** have to start greenfield, and Cbox ID never forces its own `users`
table on you. The whole platform references a person by an **opaque string id**
through one contract — `Cbox\Id\Identity\Contracts\Subjects`. Bind your own
implementation and every part of Cbox ID (sessions, MFA, passkeys, SSO, OAuth) runs
against *your* existing user store.

```
Cbox ID  ──asks──►  Subjects (contract)  ──you implement──►  your users table
 (never owns users)      find / create / verifyPassword …        (Passport, Sanctum, homegrown…)
```

## 1. Point Cbox ID at your existing users

Implement the contract over your model, and bind it in config. That's the whole
integration.

```php
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\ValueObjects\Subject;
use App\Models\User;

final class AppSubjects implements Subjects
{
    public function find(string $id): ?Subject
    {
        return ($u = User::find($id)) ? new Subject($u->id, $u->email, $u->name) : null;
    }

    public function findByEmail(string $email): ?Subject
    {
        return ($u = User::whereEmail($email)->first()) ? new Subject($u->id, $u->email, $u->name) : null;
    }

    public function create(string $email, ?string $name = null, ?string $password = null): Subject
    {
        $u = User::create(['email' => $email, 'name' => $name, 'password' => $password ? Hash::make($password) : null]);
        return new Subject($u->id, $u->email, $u->name);
    }

    public function verifyPassword(string $subjectId, string $password): bool
    {
        $u = User::find($subjectId);
        return $u !== null && Hash::check($password, (string) $u->password);
    }

    public function setPassword(string $subjectId, string $password): void
    {
        User::whereKey($subjectId)->update(['password' => Hash::make($password)]);
    }

    // provisionFederated(), link(), linkedIdentities(), unlink() — implement these
    // when you enable SSO/social login (they map an external identity to a user).
}
```

```php
// config/cbox-id.php
'subject' => ['resolver' => App\Identity\AppSubjects::class],
```

Ids are opaque, so anything works: an auto-increment id, a ULID, even a namespaced
id (`"reseller:42"`) if you have several authenticatable models. **Cbox ID stores no
PII it can't delete through your resolver** — good for GDPR erasure.

> The package ships a default `DatabaseSubjects` over an optional users table for
> greenfield installs. Binding your own resolver replaces it entirely.

## 2. Taking over from Laravel Passport

Passport turns *your app* into an OAuth2 server issuing tokens to its own clients.
Cbox ID is also an OAuth2/OIDC server — but a **dedicated identity provider** with
MFA, passkeys, SSO, SCIM, and a hosted login. The migration is incremental; you
never need a big-bang cutover.

**Recommended path — run Cbox ID as the IdP, keep your users:**

1. **Keep your `users` table.** Bind it via `Subjects` (step 1). No user migration.
2. **Register your existing OAuth clients** in Cbox ID — one `oauth_clients` row per
   Passport client (same `redirect_uri`s), or let them self-register via
   [Dynamic Client Registration](../security/standards.md) (`cbox-id.oauth.dynamic_registration`).
3. **Repoint your apps** from Passport's `/oauth/authorize` + `/oauth/token` to
   Cbox ID's — the endpoints are standard OAuth2/OIDC, so most clients only need the
   base URL changed. Cbox ID adds PKCE, `at+jwt` access tokens, refresh-token
   rotation with reuse detection, and optional DPoP (RFC 9449) sender-constrained
   tokens you didn't have before.
4. **Drain, don't cut.** Passport access tokens are short-lived; let them expire.
   Refresh tokens re-issue against Cbox ID on next refresh (users re-consent once).
5. **Retire Passport** once traffic has moved. Remove `Passport::routes()` and the
   `passport` tables when the dashboards show zero issuance.

**Verifying tokens during the overlap:** Cbox ID publishes a JWKS at
`/.well-known/jwks.json` and metadata at `/.well-known/openid-configuration` (+ the
RFC 8414 `/.well-known/oauth-authorization-server`). Resource servers validate
Cbox ID tokens against that JWKS while still accepting Passport tokens, then drop
Passport verification when it's drained.

## 3. Unified auth across two (or more) products

The classic "we have two products and want one login" setup. Make Cbox ID the
**central IdP**; each product is an OpenID Connect **client**.

```
                 ┌──────────────┐
 Product A  ◄──► │              │
   (OIDC RP)     │   Cbox ID    │  one identity, one MFA/passkey enrollment,
                 │    (IdP)     │  one session, one SCIM/SSO surface
 Product B  ◄──► │              │
   (OIDC RP)     └──────────────┘
```

- Each product runs a standard **OIDC client** (Laravel Socialite's `generic`
  driver, or `league/oauth2-client`), pointed at Cbox ID's discovery document.
- A user signs in **once** at Cbox ID; each product receives an `id_token` and gets
  the same canonical `sub` — so "who is this person" is identical across products.
- MFA, passkeys, recovery codes, session revocation, and step-up live **once** at
  the IdP, not re-implemented per product.

**Sharing the actual user records:** if both products already have their own user
tables, bind a `Subjects` resolver that maps a Cbox ID subject to the canonical
record (e.g. a shared identity service, or product A's users as the source of
truth). New products then read identity from Cbox ID instead of maintaining their
own login.

## 4. Unifying tenancy

Cbox ID ships an Organization + Membership model (users belong to orgs with roles),
with deny-by-default tenant isolation. Two ways to unify:

- **Adopt it:** model your customers as Cbox ID organizations; memberships carry the
  roles, and SCIM/SSO provisioning maps groups onto them. Products read org context
  from the token (`org` claim) and the membership API.
- **Bridge it:** keep your existing tenant model and map Cbox ID orgs to it in your
  resolver/claims — the `org` claim and membership checks still gate access, backed
  by your own tenant ids.

Either way the tenancy decision is one integration point, not a rewrite.

## Where to go next

- [Extending](../extension-points/index.md) — swap any contract (Subjects, validators, stores).
- [Standards](../security/standards.md) — the OAuth/OIDC/SCIM endpoints your apps integrate against.
- [Security](../security/index.md) — the isolation and crypto invariants you inherit.
- Run `php artisan cbox-id:install` then `php artisan cbox-id:doctor` to bootstrap
  and verify the setup.
