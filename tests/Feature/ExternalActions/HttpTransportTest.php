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

/**
 * A VERB THE TRANSPORT DOES NOT RECOGNISE IS AN UNANSWERED GATE, not permission.
 *
 * `($json['action'] ?? 'continue') === 'deny'` continued on everything that was not
 * exactly `deny`. The case that bites is casing: a customer's handler answering
 * `{"action":"DENY","reason":"..."}` had its refusal ignored on every request, and because
 * the response was 2xx nothing recorded a failure — their dashboard showed the hook firing
 * successfully while it blocked nothing.
 *
 * `TokenMinting` is `FailClosed` ({@see HookPoint::failPolicy()}, "an unanswered gate must
 * not read as permission"), so an unrecognised verb must land there.
 */
it('refuses a 2xx reply whose action it cannot recognise', function (string $body): void {
    config()->set('cbox-id.external_actions.verify_url', false);
    Http::fake(['*' => Http::response(json_decode($body, true), 200)]);

    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');
    $result = app(ActionTransport::class)->send($registered->endpoint, new ActionContext(HookPoint::TokenMinting, []));

    expect($result->allowed)->toBeFalse();
})->with([
    'absent action' => '{"claims":{}}',
    'misspelled' => '{"action":"denied"}',
    'unknown verb' => '{"action":"maybe"}',
    'non-string' => '{"action":true}',
]);

/**
 * …and the mirror: a verb that differs only in CASE is honoured rather than refused.
 *
 * Refusing `DENY` would also be failing closed, so the test above passes either way for
 * that input — but it would mean a correctly-refusing hook is reported as broken, and the
 * fix for that is the one that reintroduces the hole. A JSON verb is prose from another
 * team's codebase, not a protocol token.
 */
it('honours a deny that differs only in case', function (): void {
    config()->set('cbox-id.external_actions.verify_url', false);
    Http::fake(['*' => Http::response(['action' => 'DENY', 'reason' => 'blocked domain'], 200)]);

    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');
    $result = app(ActionTransport::class)->send($registered->endpoint, new ActionContext(HookPoint::TokenMinting, []));

    expect($result->allowed)->toBeFalse()
        ->and($result->reason)->toBe('blocked domain');
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
