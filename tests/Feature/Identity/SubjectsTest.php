<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Models\IdentityLink;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('creates a subject and finds it by email or id', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('alice@example.com', 'Alice');

    expect($subject->email)->toBe('alice@example.com')
        ->and($subjects->findByEmail('alice@example.com')?->id)->toBe($subject->id)
        ->and($subjects->find($subject->id)?->id)->toBe($subject->id);
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

it('emits an event and records audit on subject creation', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    $this->makeUser('e@example.com');

    $events->assertEmitted('user.created');
    $audit->assertRecorded('user.created');
});
