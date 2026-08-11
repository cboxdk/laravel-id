<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Manifest\Manifest;
use Cbox\Id\AccessControl\ManifestSyncService;
use Cbox\Id\Migration\Models\LegacyLoginDeclarationRecord;
use Cbox\Id\Migration\Sources\DeclaredCredentialSource;
use Cbox\Id\Migration\ValueObjects\LegacyLoginDeclaration;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config()->set('cbox-id.migration.verify_url', false);
});

function declare_(string $url = 'https://legacy.acme.test/verify', string $client = 'client-a'): void
{
    app(ManifestSyncService::class)->sync($client, new Manifest(
        version: 'v'.mt_rand(),
        permissions: [],
        roles: [],
        legacyLogin: new LegacyLoginDeclaration($url, str_repeat('s', 40)),
    ));
}

/**
 * THE PROPERTY THE WHOLE DESIGN RESTS ON. A role an app declares affects that app; this
 * declares where every unknown email and the password typed with it goes. A client holding
 * `apps.manifest` that could enable it unilaterally would be a credential harvester with a
 * scope for the purpose.
 */
it('does nothing at all until a person approves it', function (): void {
    Http::fake(['*' => Http::response(['email' => 'ada@legacy.test'], 200)]);

    declare_();

    expect(LegacyLoginDeclarationRecord::query()->count())->toBe(1)
        ->and(LegacyLoginDeclarationRecord::query()->first()?->isApproved())->toBeFalse();

    // The source behaves exactly as if nothing were configured.
    expect(app(DeclaredCredentialSource::class)->verify('ada@legacy.test', 'pw'))->toBeNull();

    Http::assertNothingSent();
});

it('carries the sign-in through once approved', function (): void {
    Http::fake(['*' => Http::response(['email' => 'ada@legacy.test', 'name' => 'Ada'], 200)]);

    declare_();
    LegacyLoginDeclarationRecord::query()->update(['approved_at' => now()]);

    $user = app(DeclaredCredentialSource::class)->verify('ada@legacy.test', 'pw');

    expect($user?->email)->toBe('ada@legacy.test');
});

/**
 * "The app changed where passwords go" is precisely the event that must not pass
 * unnoticed — a compromised deploy pipeline is otherwise one manifest push away from
 * redirecting the login path to somewhere else.
 */
it('drops the approval when the app declares a different url', function (): void {
    declare_();
    LegacyLoginDeclarationRecord::query()->update(['approved_at' => now()]);

    declare_('https://somewhere-else.test/verify');

    $record = LegacyLoginDeclarationRecord::query()->first();

    expect($record?->url)->toBe('https://somewhere-else.test/verify')
        ->and($record?->isApproved())->toBeFalse();
});

/**
 * A routine redeploy republishes the same manifest. Losing the approval every time would
 * mean an operator re-approving on every release, and an approval people click without
 * reading is not a control.
 */
it('keeps the approval when the same url is redeclared', function (): void {
    declare_();
    LegacyLoginDeclarationRecord::query()->update(['approved_at' => now()]);

    declare_();

    expect(LegacyLoginDeclarationRecord::query()->first()?->isApproved())->toBeTrue();
});

it('refuses a declaration that would send passwords in the clear', function (): void {
    expect(fn () => new LegacyLoginDeclaration('http://legacy.acme.test/verify', str_repeat('s', 40)))
        ->toThrow(InvalidArgumentException::class);
});

/**
 * The secret is the only thing proving a request came from us; a short one makes the
 * signature decorative, and a customer who picked "changeme" would never hear about it.
 */
it('refuses a secret too short to mean anything', function (): void {
    expect(fn () => new LegacyLoginDeclaration('https://legacy.acme.test/verify', 'changeme'))
        ->toThrow(InvalidArgumentException::class);
});

it('seals the secret rather than storing it in the clear', function (): void {
    declare_();

    $record = LegacyLoginDeclarationRecord::query()->firstOrFail();

    // The URL is readable on purpose — an operator has to see it before approving — and
    // the secret is not.
    expect($record->url)->toContain('legacy.acme.test')
        ->and($record->secret_encrypted)->not->toContain(str_repeat('s', 40));
});
