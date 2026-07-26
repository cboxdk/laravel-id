<?php

declare(strict_types=1);

use Cbox\Id\ExternalActions\Contracts\ActionTransport;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\Tests\Support\WebhookSignatureFixture;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

it('signs the request and interprets an enrich reply', function (): void {
    config()->set('cbox-id.external_actions.verify_url', false);
    Http::fake(['*' => Http::response(['action' => 'continue', 'claims' => ['x' => 1]], 200)]);

    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');
    $result = app(ActionTransport::class)->send($registered->endpoint, new ActionContext(HookPoint::TokenMinting, ['client_id' => 'c1']));

    expect($result->allowed)->toBeTrue()
        ->and($result->enrichment)->toBe(['x' => 1]);

    Http::assertSent(fn (Request $req): bool => $req->hasHeader('X-Cbox-Timestamp')
        && str_contains($req->header('X-Cbox-Signature')[0], 'v1='));
});

it('signs an inline action with the same wire format the shared webhook fixture pins', function (): void {
    // Inline actions reuse the webhook signing scheme, and the SDKs verify both with
    // ONE function (`verifyWebhook`, documented for "webhook / inline-action"). But
    // the assertion above only checks the header CONTAINS `v1=` — the MAC itself was
    // never verified here, so this surface could drift away from the webhook format
    // (or stop signing meaningfully at all) undetected.
    config()->set('cbox-id.external_actions.verify_url', false);
    Http::fake(['*' => Http::response(['action' => 'continue'], 200)]);

    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');
    app(ActionTransport::class)->send($registered->endpoint, new ActionContext(HookPoint::TokenMinting, ['client_id' => 'c1']));

    Http::assertSent(function (Request $req) use ($registered): bool {
        // The concatenation order comes from the shared cross-SDK fixture, not from a
        // local copy of the formula.
        expect($req->header('X-Cbox-Signature')[0])->toBe(WebhookSignatureFixture::expectedHeader(
            $req->header('X-Cbox-Timestamp')[0],
            $req->body(),
            $registered->secret,
        ));

        return true;
    });
});

it('interprets a deny reply', function (): void {
    config()->set('cbox-id.external_actions.verify_url', false);
    Http::fake(['*' => Http::response(['action' => 'deny', 'reason' => 'user is blocked'], 200)]);

    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');
    $result = app(ActionTransport::class)->send($registered->endpoint, new ActionContext(HookPoint::TokenMinting, []));

    expect($result->allowed)->toBeFalse()
        ->and($result->reason)->toBe('user is blocked');
});

it('fails closed on a non-2xx reply', function (): void {
    config()->set('cbox-id.external_actions.verify_url', false);
    Http::fake(['*' => Http::response('nope', 500)]);

    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');
    $result = app(ActionTransport::class)->send($registered->endpoint, new ActionContext(HookPoint::TokenMinting, []));

    expect($result->allowed)->toBeFalse();
});

it('fails open on a transport error only when configured', function (): void {
    config()->set('cbox-id.external_actions.verify_url', false);
    config()->set('cbox-id.external_actions.fail_open', true);
    Http::fake(['*' => Http::response('nope', 502)]);

    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');
    $result = app(ActionTransport::class)->send($registered->endpoint, new ActionContext(HookPoint::TokenMinting, []));

    expect($result->allowed)->toBeTrue();
});
