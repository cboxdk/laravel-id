<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * @group isolation
 *
 * Identity is environment-scoped: the same email is a DIFFERENT person in two
 * environments (staging-Alice ≠ prod-Alice), sessions never cross environments,
 * and a federated identity resolves within its environment only.
 */
it('treats the same email as distinct users per environment', function (): void {
    $subjects = app(Subjects::class);

    $a = $this->runAsEnvironment('env_a', fn () => $subjects->create('alice@corp.com', 'A'));
    $b = $this->runAsEnvironment('env_b', fn () => $subjects->create('alice@corp.com', 'B'));

    expect($a->id)->not->toBe($b->id);

    // From env_a you resolve env_a's Alice, never env_b's.
    $this->actingAsEnvironment('env_a');
    expect($subjects->findByEmail('alice@corp.com')?->id)->toBe($a->id)
        ->and($subjects->find($b->id))->toBeNull();
});

it('never treats a session as active across environments', function (): void {
    $sessions = app(SessionManager::class);
    $session = $this->runAsEnvironment('env_a', fn () => $sessions->start('user-1', null, ['pwd']));

    $this->runAsEnvironment('env_a', fn () => expect($sessions->active($session->id))->not->toBeNull());
    $this->runAsEnvironment('env_b', fn () => expect($sessions->active($session->id))->toBeNull());
});

it('resolves a federated identity within its environment only', function (): void {
    $subjects = app(Subjects::class);
    $principal = new FederatedPrincipal('social:google', 'google|1', 'g@corp.com', 'G');

    $a = $this->runAsEnvironment('env_a', fn () => $subjects->provisionFederated($principal));
    $b = $this->runAsEnvironment('env_b', fn () => $subjects->provisionFederated($principal));

    // Same provider subject, two environments → two separate accounts.
    expect($a->id)->not->toBe($b->id);
});

it('scopes MFA factors to their environment', function (): void {
    $factor = $this->runAsEnvironment('env_a', fn () => MfaFactor::create([
        'user_id' => 'user-1', 'type' => 'totp', 'secret_encrypted' => 'sealed',
    ]));

    // Auto-stamped on create.
    expect($factor->environment_id)->toBe('env_a');

    // Invisible from env_b — even by primary key.
    $this->runAsEnvironment('env_b', function () use ($factor): void {
        expect(MfaFactor::count())->toBe(0)
            ->and(MfaFactor::find($factor->id))->toBeNull();
    });

    // Still reachable from its own environment.
    $this->runAsEnvironment('env_a', fn () => expect(MfaFactor::find($factor->id))->not->toBeNull());
})->group('isolation');
