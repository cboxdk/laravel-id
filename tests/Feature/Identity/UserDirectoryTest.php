<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\UserDirectory;
use Cbox\Id\Identity\Models\IdentityLink;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('creates a user and finds it by email or id', function (): void {
    $directory = app(UserDirectory::class);
    $user = $directory->create('alice@example.com', 'Alice');

    expect($user->email)->toBe('alice@example.com')
        ->and($directory->findByEmail('alice@example.com')?->id)->toBe($user->id)
        ->and($directory->find($user->id)?->id)->toBe($user->id);
});

it('verifies passwords with a real hash', function (): void {
    $directory = app(UserDirectory::class);
    $user = $directory->create('bob@example.com', null, 'correct-horse-battery');

    expect($directory->verifyPassword($user, 'correct-horse-battery'))->toBeTrue()
        ->and($directory->verifyPassword($user, 'wrong'))->toBeFalse()
        ->and($user->password)->not->toBe('correct-horse-battery'); // stored hashed
});

it('sets a new password', function (): void {
    $directory = app(UserDirectory::class);
    $user = $directory->create('c@example.com');

    expect($directory->verifyPassword($user, 'anything'))->toBeFalse(); // none set

    $directory->setPassword($user, 'newpass');

    expect($directory->verifyPassword($user, 'newpass'))->toBeTrue();
});

it('provisions a federated identity idempotently', function (): void {
    $directory = app(UserDirectory::class);
    $principal = new FederatedPrincipal('saml', 'okta|123', 'dana@corp.com', 'Dana', 'conn_1');

    $first = $directory->provisionFederated($principal);
    $second = $directory->provisionFederated($principal);

    expect($second->id)->toBe($first->id)
        ->and($first->email)->toBe('dana@corp.com')
        ->and(User::query()->count())->toBe(1)
        ->and(IdentityLink::query()->count())->toBe(1);
});

it('emits an event and records audit on user creation', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    $this->makeUser('e@example.com');

    $events->assertEmitted('user.created');
    $audit->assertRecorded('user.created');
});
