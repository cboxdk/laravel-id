---
title: Migrating users off another system
description: Bulk import with existing hashes, and — when you cannot export them — delegated authentication that imports each person at the moment they sign in
weight: 16
---

# Migrating users off another system

Nobody changes identity provider if it means emailing every customer a password reset.
Two mechanisms exist so you do not have to, and they are complementary rather than
alternatives.

## First: bulk import

[`UserImport`](../extension-points/_index.md) moves users **with their existing password
hashes**. Each foreign hash is verified by the same registry the platform uses for its
own, and transparently upgraded to the platform hasher on that person's first successful
login. Nobody notices anything.

```php
app(UserImport::class)->import($organizationId, $users, new ImportOptions(upsert: true));
```

This is the better answer whenever it is available: it is one pass, it is auditable, and
the old system can be switched off the same day.

It requires that you can **export** the hashes.

## When you cannot export: delegated authentication

Often you cannot. The hashes sit in a system with no dump, or in a format nothing
recognises, or behind an API somebody else owns.

So the verification moves instead of the data. An email nobody here knows is offered to
the old system, and if it says yes, the person is created here **as a result of the login
that just succeeded**. The next time they sign in they are an ordinary local user and the
old system is never consulted again.

Bind a source:

```php
use Cbox\Id\Migration\Contracts\LegacyCredentialSource;
use Cbox\Id\Migration\Sources\DatabaseCredentialSource;

$this->app->singleton(LegacyCredentialSource::class, fn ($app) => new DatabaseCredentialSource(
    $app['db'],
    $app[HashVerifier::class],
    connection: 'legacy',          // configure it read-only
    table: 'users',
    columns: [
        'email' => 'email',
        'name' => 'name',
        'password' => 'password',
        'verified_at' => 'email_verified_at',
    ],
));
```

That covers the common case by a distance: an old Laravel, Rails or PHP app with a `users`
table of bcrypt hashes in a database you still have credentials for.

For anything else — a mainframe, a SaaS with an authentication endpoint and no export —
there is an HTTP bridge:

```php
new HttpCredentialSource($app[Factory::class], $app[UrlGuard::class],
    url: 'https://legacy.acme.com/cbox-verify',
    secret: config('services.legacy.secret'),
);
```

Your handler receives a signed POST and answers with the person, or refuses:

```json
{ "email": "ada@acme.com", "name": "Ada Lovelace", "email_verified": true }
```

Returning `password_hash` as well lets the person keep their password here verbatim; if
your system cannot expose it, omit it and the password they just proved is hashed with
the platform hasher instead. Both are legitimate.

The request is signed exactly the way [external actions](external-actions.md) are —
`X-Cbox-Signature: t=…,v1=…` over `"{timestamp}.{body}"` — so a verifier you have already
written works here unchanged.

> **Why not a script sandbox?** Auth0 solves this by running your JavaScript inside their
> runtime. That is a code-execution surface in the authentication path, where a customer's
> bug becomes the provider's incident. An HTTP hop buys the same flexibility with the
> blast radius on the side that wrote the code.

## Declaring it from your app instead

Configuring the URL in one place and the secret in another is two places that drift. Your
app already declares facts about itself through the manifest — its roles, its permissions,
versioned with the deploy — and where its old login lives is the same kind of fact:

```ts
export default defineAuthz({
  roles: [...],
  legacyLogin: {
    url: 'https://acme.com/api/cbox-legacy',
    secret: process.env.CBOX_LEGACY_SECRET!,
  },
})
```

**A declaration arrives inert.** Everything else in a manifest affects only the app that
declared it; this one names a URL that every unknown email and the password typed with it
will be offered to, on the environment's whole sign-in path. A client holding
`apps.manifest` that could switch that on by itself would be a credential harvester with a
scope for the purpose.

So it is stored, shown to an operator beside the app that proposed it, and does nothing
until a person approves it. Re-declaring the **same** URL keeps that approval — a routine
redeploy republishes the same manifest, and an approval people click through on every
release is not a control. Re-declaring a **different** URL drops it, because "the app
changed where passwords go" is precisely the event that must not pass unnoticed: a
compromised deploy pipeline is otherwise one manifest push away from redirecting the login
path.

The URL is stored readable, because an operator has to see it before approving and a value
nobody can inspect is a value nobody can check. The secret is sealed.

## Writing the handler

`@cboxdk/id-js` ships the handler so you do not write the signature check:

```ts
export const POST = createLegacyVerifier({
  secret: process.env.CBOX_LEGACY_SECRET!,
  async verify(email, password) {
    const row = await db.users.findByEmail(email)
    if (!row || !(await argon2.verify(row.password, password))) return null

    return { email: row.email, name: row.name, emailVerified: !!row.confirmedAt }
  },
})
```

Return `null` for a wrong password. **Throwing is different** and is answered with a 503:
your store could not decide, which is not the same as saying no, and the fail-closed rule
below turns it into a refusal that is distinguishable in the logs.

## Two rules, and why they are not negotiable

**A user who exists here is never offered to the old system.** Once somebody has migrated,
their password is the one in this platform, full stop. Consulting the old system for them
would let a password they changed *here* be bypassed by the one still sitting *there* —
and the old system is, by definition, the one nobody is maintaining any more.

**A source that cannot answer refuses the sign-in.** If the legacy system is down, slow or
misconfigured, an un-migrated person cannot sign in. The alternative — letting them
through because we could not check — turns an outage in the system you are migrating *off*
into an authentication bypass. Migrated users are unaffected, because of the first rule,
so the blast radius is exactly the tail you have not moved yet.

## Attaching people to organizations

The platform creates the subject; what they belong to is yours to decide. Listen for
`UserMigrated`, which carries both sides — the subject as this platform now knows them,
and the legacy record with whatever role or tenant it held:

```php
Event::listen(UserMigrated::class, function (UserMigrated $event): void {
    app(Memberships::class)->add($orgId, $event->subject->id, MembershipRole::from($event->legacy->role));
});
```

## Finishing the migration

Delegated authentication is a ramp, not a destination. Watch how many sign-ins still go
through the bridge; when the tail is thin enough to be worth a password reset, unbind the
source and send that email to the remainder. Leaving it bound forever means the old
system's availability is permanently part of your login path.

## Networking

The HTTP bridge pins DNS and refuses private address ranges by default, like every other
outbound call this package makes. A legacy system is very often on a private network —
that is what makes it legacy — so `CBOX_ID_MIGRATION_VERIFY_URL=false` exists to say so
deliberately. Plain `http` is refused regardless: a credential in the clear is readable by
everything on the path, and no configuration flag should be able to permit that.
