<?php

declare(strict_types=1);

use Cbox\Id\ExternalActions\Contracts\ActionTransport;
use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Exceptions\UnsafeActionUrl;
use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Ssrf\Testing\InteractsWithSsrf;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class, InteractsWithSsrf::class);

/*
 * An inline hook carries the person's context out and its reply is trusted to veto or add
 * claims, with nothing but the transport to protect either: https only, and the delivery
 * pinned to the address that was checked, however the verification toggle is spelled.
 */

function hookDns(array $dns): void
{
    test()->fakeSsrfDns($dns);
    app()->forgetInstance(ActionTransport::class);
    app()->forgetInstance(ExternalActions::class);
}

it('refuses to register a plaintext http hook', function (): void {
    hookDns(['plain.example.test' => ['93.184.216.34']]);

    expect(fn () => $this->registerActionEndpoint(HookPoint::TokenMinting, 'http://plain.example.test/mint'))
        ->toThrow(UnsafeActionUrl::class)
        ->and(ExternalActionEndpoint::query()->count())->toBe(0);
});

it('sends nothing to a stored http hook, and the gate fails closed', function (): void {
    hookDns(['plain.example.test' => ['93.184.216.34']]);
    Http::fake(['*' => Http::response(['action' => 'continue', 'claims' => ['injected' => 'by-network']], 200)]);

    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://plain.example.test/mint');
    // A row from before the scheme was enforced.
    ExternalActionEndpoint::query()->whereKey($registered->endpoint->id)->update(['url' => 'http://plain.example.test/mint']);

    $result = app(ActionTransport::class)->send($registered->endpoint->fresh(), new ActionContext(HookPoint::TokenMinting, ['client_id' => 'c1']));

    expect($result->allowed)->toBeFalse()
        ->and($result->enrichment)->toBe([]);

    Http::assertNothingSent();
});

it('pins delivery to the checked address whatever truthy spelling turns verification on', function (mixed $toggle): void {
    config(['cbox-id.external_actions.verify_url' => $toggle]);
    hookDns(['rebind.example.test' => ['93.184.216.34']]);
    Http::fake(['*' => Http::response(['action' => 'continue', 'claims' => ['reached' => true]], 200)]);

    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://rebind.example.test/mint');

    // Rebound to the metadata service after registration.
    hookDns(['rebind.example.test' => ['169.254.169.254']]);

    $transport = app(ActionTransport::class);
    $context = new ActionContext(HookPoint::TokenMinting, ['client_id' => 'c1']);

    expect($transport->send($registered->endpoint, $context)->allowed)->toBeFalse()
        ->and(array_values($transport->sendMany(collect([$registered->endpoint]), $context))[0]->allowed)->toBeFalse();

    Http::assertNothingSent();
})->with(['1', 'on', 'yes', 'true', true, 1]);
