<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\AppManifestPuller;
use Cbox\Id\AccessControl\Contracts\ManifestFetcher;
use Cbox\Id\AccessControl\Exceptions\ManifestFetchFailed;
use Cbox\Id\AccessControl\Exceptions\UnsafeManifestUrl;
use Cbox\Id\AccessControl\Jobs\SyncAppManifestJob;
use Cbox\Id\AccessControl\Models\Role;
use Cbox\Id\OAuthServer\Models\Client;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;

uses(RefreshDatabase::class);

/**
 * @return array<string, mixed>
 */
function manifestBody(): array
{
    return [
        'version' => 'v1',
        'permissions' => [['key' => 'invoices:read', 'description' => 'View invoices']],
        'roles' => [['key' => 'viewer', 'name' => 'Viewer', 'permissions' => ['invoices:read']]],
    ];
}

function makeClient(?string $manifestUrl): Client
{
    return Client::query()->create([
        'client_id' => 'app_billing',
        'name' => 'Billing',
        'type' => 'confidential',
        'manifest_url' => $manifestUrl,
    ]);
}

it('fetches + parses a published manifest', function (): void {
    config(['cbox-id.access_control.verify_manifest_url' => false]); // no real DNS in the test
    Http::fake(['https://app.acme.test/*' => Http::response(manifestBody(), 200)]);

    $manifest = app(ManifestFetcher::class)->fetch('https://app.acme.test/.well-known/cbox-authz');

    expect($manifest->version)->toBe('v1')
        ->and($manifest->roleKeys())->toBe(['viewer'])
        ->and($manifest->permissionKeys())->toBe(['invoices:read']);
});

it('refuses a manifest URL that fails the SSRF guard', function (): void {
    // Guard on (default): a loopback address is blocked before any request is made.
    expect(fn () => app(ManifestFetcher::class)->fetch('http://127.0.0.1/.well-known/cbox-authz'))
        ->toThrow(UnsafeManifestUrl::class);
});

it('fails cleanly on a non-2xx or non-JSON response', function (): void {
    config(['cbox-id.access_control.verify_manifest_url' => false]);
    Http::fake(['https://app.acme.test/*' => Http::response('nope', 404)]);

    expect(fn () => app(ManifestFetcher::class)->fetch('https://app.acme.test/.well-known/cbox-authz'))
        ->toThrow(ManifestFetchFailed::class);
});

it('pulls + syncs an app from its manifest_url', function (): void {
    config(['cbox-id.access_control.verify_manifest_url' => false]);
    Http::fake(['https://app.acme.test/*' => Http::response(manifestBody(), 200)]);

    $client = makeClient('https://app.acme.test/.well-known/cbox-authz');
    $result = app(AppManifestPuller::class)->pull($client);

    expect($result)->not->toBeNull()
        ->and($result->rolesDeclared)->toBe(1);
    expect(Role::query()->where('client_id', 'app_billing')->where('key', 'viewer')->exists())->toBeTrue();
});

it('does nothing for an app that publishes no manifest_url (it pushes instead)', function (): void {
    $client = makeClient(null);

    expect(app(AppManifestPuller::class)->pull($client))->toBeNull();
});

it('dispatches one sync job per app that publishes a manifest_url', function (): void {
    Queue::fake();
    makeClient('https://app.acme.test/.well-known/cbox-authz');
    Client::query()->create(['client_id' => 'app_nopull', 'name' => 'No Pull', 'type' => 'confidential']);

    $this->artisan('cbox-id:app-manifests:sync')->assertSuccessful();

    Queue::assertPushed(SyncAppManifestJob::class, 1);
});
