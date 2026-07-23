<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Exceptions\AccountExistsForEmail;
use Cbox\Id\Identity\Exceptions\IdentityAlreadyLinked;
use Cbox\Id\Identity\Models\IdentityLink;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Identity\ValueObjects\LinkedIdentity;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('creates a subject and finds it by email or id', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('alice@example.com', 'Alice');

    expect($subject->email)->toBe('alice@example.com')
        ->and($subjects->findByEmail('alice@example.com')?->id)->toBe($subject->id)
        ->and($subjects->find($subject->id)?->id)->toBe($subject->id);
});

it('reports email verification on the subject so relying parties can trust the address', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('carol@example.com', 'Carol');

    // A fresh subject is unverified — a relying party must not adopt/link on this.
    expect($subjects->find($subject->id)?->emailVerified)->toBeFalse();

    $subjects->markEmailVerified($subject->id, 'carol@example.com');

    expect($subjects->find($subject->id)?->emailVerified)->toBeTrue();
});

it('verifies passwords with a real hash', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('bob@example.com', null, 'correct-horse-battery');

    expect($subjects->verifyPassword($subject->id, 'correct-horse-battery'))->toBeTrue()
        ->and($subjects->verifyPassword($subject->id, 'wrong'))->toBeFalse()
        ->and(User::query()->whereKey($subject->id)->first()?->password)->not->toBe('correct-horse-battery'); // stored hashed
});

it('sets a new password', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('c@example.com');

    expect($subjects->verifyPassword($subject->id, 'anything'))->toBeFalse(); // none set

    $subjects->setPassword($subject->id, 'newpass');

    expect($subjects->verifyPassword($subject->id, 'newpass'))->toBeTrue();
});

it('provisions a federated identity idempotently', function (): void {
    $subjects = app(Subjects::class);
    $principal = new FederatedPrincipal('saml', 'okta|123', 'dana@corp.com', 'Dana', 'conn_1');

    $first = $subjects->provisionFederated($principal);
    $second = $subjects->provisionFederated($principal);

    expect($second->id)->toBe($first->id)
        ->and($first->email)->toBe('dana@corp.com')
        ->and(User::query()->count())->toBe(1)
        ->and(IdentityLink::query()->count())->toBe(1);
});

it('scopes federated identities per SSO connection so one org IdP cannot hijack another', function (): void {
    $subjects = app(Subjects::class);

    // Org B's trusted SAML connection provisions Alice.
    $alice = $subjects->provisionFederated(
        new FederatedPrincipal('saml', 'alice@corp.com', 'alice@corp.com', 'Alice', 'conn_orgB')
    );

    // A DIFFERENT org's (attacker-controlled) connection asserts the SAME NameID,
    // with no email so the email-collision guard doesn't even engage.
    $imposter = $subjects->provisionFederated(
        new FederatedPrincipal('saml', 'alice@corp.com', null, 'Not Alice', 'conn_orgA')
    );

    // The subject namespaces are isolated: the impostor gets a fresh account, not Alice's.
    expect($imposter->id)->not->toBe($alice->id)
        ->and(User::query()->count())->toBe(2)
        ->and(IdentityLink::query()->count())->toBe(2);

    // Re-asserting through the SAME connection is still idempotent (returns Alice).
    expect($subjects->provisionFederated(
        new FederatedPrincipal('saml', 'alice@corp.com', 'alice@corp.com', 'Alice', 'conn_orgB')
    )->id)->toBe($alice->id);
});

it('refuses to merge a federated identity into an existing account by email', function (): void {
    $subjects = app(Subjects::class);
    // An account already exists (e.g. created with a password).
    $subjects->create('dana@corp.com', 'Dana', 'secret-password');

    // A *different* provider identity shows up with the same email.
    $subjects->provisionFederated(new FederatedPrincipal('social:google', 'google|999', 'dana@corp.com', 'Dana'));
})->throws(AccountExistsForEmail::class);

it('links a provider identity explicitly to an authenticated subject', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('dana@corp.com', 'Dana');

    $subjects->link($subject->id, new FederatedPrincipal('social:github', 'gh|1', 'dana@corp.com'));

    // The linked identity now resolves back to the same subject.
    $resolved = $subjects->provisionFederated(new FederatedPrincipal('social:github', 'gh|1', 'dana@corp.com'));
    expect($resolved->id)->toBe($subject->id)
        ->and($subjects->linkedIdentities($subject->id))->toContainEqual(new LinkedIdentity('social:github', 'gh|1'));
});

it('links the same social identity idempotently without creating a duplicate row', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('dana@corp.com', 'Dana');

    // A social provider has a null connection_id, so the natural uniqueness index
    // does not dedupe it at the DB level — the guarded check-then-insert must.
    $principal = new FederatedPrincipal('social:github', 'gh|1', 'dana@corp.com');
    $subjects->link($subject->id, $principal);
    $subjects->link($subject->id, $principal);

    expect(IdentityLink::query()->where('user_id', $subject->id)->count())->toBe(1);
});

it('refuses to link an identity already owned by another account', function (): void {
    $subjects = app(Subjects::class);
    $a = $subjects->create('a@corp.com');
    $b = $subjects->create('b@corp.com');

    $subjects->link($a->id, new FederatedPrincipal('social:google', 'google|1', 'a@corp.com'));

    $subjects->link($b->id, new FederatedPrincipal('social:google', 'google|1', 'a@corp.com'));
})->throws(IdentityAlreadyLinked::class);

it('unlinks a provider identity', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('dana@corp.com');
    $subjects->link($subject->id, new FederatedPrincipal('social:google', 'google|1'));

    $subjects->unlink($subject->id, 'social:google');

    expect($subjects->linkedIdentities($subject->id))->toBeEmpty();
});

it('emits an event and records audit on subject creation', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    $this->makeUser('e@example.com');

    $events->assertEmitted('user.created');
    $audit->assertRecorded('user.created');
});

it('treats a fresh subject as active', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('active@example.com');

    expect($subjects->isActive($subject->id))->toBeTrue();
});

it('deactivating a subject blocks password auth and marks it inactive', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('gone@example.com', null, 'correct-horse-battery');
    expect($subjects->verifyPassword($subject->id, 'correct-horse-battery'))->toBeTrue();

    $subjects->deactivate($subject->id);

    // The right password no longer authenticates a disabled account.
    expect($subjects->isActive($subject->id))->toBeFalse()
        ->and($subjects->verifyPassword($subject->id, 'correct-horse-battery'))->toBeFalse();

    // Reactivation restores it.
    $subjects->reactivate($subject->id);
    expect($subjects->isActive($subject->id))->toBeTrue()
        ->and($subjects->verifyPassword($subject->id, 'correct-horse-battery'))->toBeTrue();
});

it('reports an unknown subject as inactive', function (): void {
    expect(app(Subjects::class)->isActive('nope'))->toBeFalse();
});
