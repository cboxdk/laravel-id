<?php

declare(strict_types=1);

use Cbox\Id\Tests\Support\WebhookSignatureFixture;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

beforeEach(fn () => config(['cbox-id.webhooks.verify_url' => false]));

/**
 * The shared cross-SDK webhook-signature fixture. The SAME file is asserted against
 * by id-js, id-python, id-go and laravel-id-client, so it is what keeps the sender
 * and the four verifiers on one wire format.
 *
 * Before it existed, every side re-implemented the signing formula inside its own
 * test — `hash_hmac('sha256', $ts.'.'.$body, $secret)` here, the same expression in
 * each SDK — so flipping the signed string to `body.ts` in the dispatcher left every
 * suite green while every customer's verification broke. Nothing below computes the
 * concatenation locally: the order comes from the fixture's template, via
 * {@see WebhookSignatureFixture}.
 */
it('is an honest HMAC vector for every fixture case', function (array $case): void {
    // The fixture's bytes really do hash to its published signature (these were also
    // reproduced independently with OpenSSL and Python), so a later edit cannot
    // quietly weaken the contract by regenerating expectations from the code.
    expect(hash_hmac('sha256', $case['signed_payload'], $case['secret']))->toBe($case['signature'])
        ->and($case['header'])->toBe('t='.$case['timestamp'].',v1='.$case['signature']);

    // And the flipped concatenation is genuinely a different MAC — the property the
    // whole fixture exists to defend.
    expect($case['reversed_order_signature'])->not->toBe($case['signature'])
        ->and(hash_hmac('sha256', $case['body'].'.'.$case['timestamp'], $case['secret']))
        ->toBe($case['reversed_order_signature']);
})->with(WebhookSignatureFixture::dataset());

it('signs a real delivery exactly as the shared fixture specifies', function (): void {
    Http::fake(['*' => Http::response('', 200)]);
    $registered = $this->registerWebhook('org_a', 'https://hook.test/x', ['organization.member_added']);

    app(WebhookDispatcher::class)->dispatch('organization.member_added', ['user_id' => 'user_1'], 'org_a');

    Http::assertSent(function (Request $request) use ($registered): bool {
        // The timestamp and delivery id are the dispatcher's, but the ORDER and the
        // header shape come from the shared fixture — flip the concatenation in
        // HttpWebhookDispatcher and this stops matching.
        $expected = WebhookSignatureFixture::expectedHeader(
            $request->header('X-Cbox-Timestamp')[0],
            $request->body(),
            $registered->secret,
        );

        expect($request->header('X-Cbox-Signature')[0])->toBe($expected);

        return true;
    });
});

it('emits a delivery envelope with the same shape the fixture pins', function (): void {
    // The fixture's golden body is only meaningful if it is the shape actually sent:
    // same members, same order, raw JSON (not form-encoded, not pretty-printed).
    Http::fake(['*' => Http::response('', 200)]);
    $this->registerWebhook('org_a', 'https://hook.test/x', ['organization.member_added']);

    app(WebhookDispatcher::class)->dispatch('organization.member_added', ['user_id' => 'user_1'], 'org_a');

    /** @var array<string, mixed> $golden */
    $golden = json_decode((string) WebhookSignatureFixture::document()['cases'][0]['body'], true, 512, JSON_THROW_ON_ERROR);

    Http::assertSent(function (Request $request) use ($golden): bool {
        /** @var array<string, mixed> $sent */
        $sent = json_decode($request->body(), true, 512, JSON_THROW_ON_ERROR);

        expect(array_keys($sent))->toBe(array_keys($golden))
            ->and($request->header('Content-Type')[0])->toStartWith('application/json');

        return true;
    });
});
