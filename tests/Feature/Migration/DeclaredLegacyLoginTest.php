<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Manifest\Manifest;
use Cbox\Id\AccessControl\ManifestSyncService;
use Cbox\Id\Migration\Models\LegacyLoginDeclarationRecord;
use Cbox\Id\Migration\Sources\DeclaredCredentialSource;
use Cbox\Id\Migration\ValueObjects\LegacyLoginDeclaration;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config()->set('cbox-id.migration.verify_url', false);
});

// Two ids, fixed for the file so an assertion can name the one it expects.
define('FIRST_CLIENT', 'cid_'.Str::lower((string) Str::ulid()));
define('SECOND_CLIENT', 'cid_'.Str::lower((string) Str::ulid()));

/**
 * A CLIENT ID SHAPED LIKE A CLIENT ID.
 *
 * This defaulted to `'client-a'` — eight characters, and nothing the registry could ever
 * mint. `ClientRegistryService` issues `'cid_'.Str::ulid()`, which is thirty, and the
 * column this row lands in was declared at twenty-six. So the insert that fails on
 * PostgreSQL and truncates on MySQL was made here with a value four engines were all happy
 * to store, and the whole engine matrix went green over a feature that could not be used.
 *
 * Minted the way the product mints it, so the row under test is the row a deployment
 * writes. Two ids are needed — the test below re-declares a URL as a different app — and
 * they have to differ, so they are generated rather than named.
 */
function clientId(): string
{
    return 'cid_'.Str::lower((string) Str::ulid());
}

function declare_(?string $url = null, ?string $client = null): void
{
    $url ??= 'https://legacy.acme.test/verify';
    $client ??= FIRST_CLIENT;

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

/**
 * THE SAME URL FROM A DIFFERENT APP IS NOT A REDEPLOY.
 *
 * The URL is shown in the console in the clear, deliberately, so anybody who can read it
 * can name it. Matching on the URL alone let any other client in the environment holding
 * `apps.manifest` re-seal an approved row with its own secret. The declaring app's handler
 * then fails every signature check — and because this path is fail-closed, every
 * un-migrated user stops being able to sign in, silently, while `client_id` names the
 * wrong app to whoever comes to investigate.
 */
it('drops the approval when a different app claims the same url', function (): void {
    declare_();
    LegacyLoginDeclarationRecord::query()->update(['approved_at' => now()]);

    declare_('https://legacy.acme.test/verify', SECOND_CLIENT);

    $record = LegacyLoginDeclarationRecord::query()->first();

    expect($record?->isApproved())->toBeFalse()
        ->and($record?->client_id)->toBe(SECOND_CLIENT)
        // The id ARRIVED WHOLE. MySQL without strict mode stores a truncated prefix rather
        // than refusing, and a client id that is four characters short matches no client —
        // so the console names nobody, which is the state this whole test is about
        // preventing. `toBe` above would catch it; this says what is being caught.
        ->and(strlen((string) $record?->client_id))->toBe(strlen(SECOND_CLIENT));
});

/**
 * An operator asking "who moved this, and when" after an incident has one place to look,
 * and it must not be a field buried in a routine sync that reads identically to one
 * renaming a role.
 */
it('records its own audit entry when an app moves where passwords go', function (): void {
    declare_();
    declare_('https://somewhere-else.test/verify');

    $entries = DB::table('audit_logs')->where('action', 'app.legacy_login_declared')->orderBy('sequence')->get();

    expect($entries)->toHaveCount(2)
        ->and(json_decode((string) $entries[0]->context, true)['change'] ?? null)->toBe('declared')
        ->and(json_decode((string) $entries[1]->context, true)['change'] ?? null)->toBe('moved')
        ->and(json_decode((string) $entries[1]->context, true)['approval_dropped'] ?? null)->toBeTrue();
});

it('says nothing in the trail when a redeploy changes nothing', function (): void {
    declare_();
    declare_();

    expect(DB::table('audit_logs')->where('action', 'app.legacy_login_declared')->count())->toBe(1);
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
