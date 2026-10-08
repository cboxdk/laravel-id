<?php

declare(strict_types=1);

use Cbox\Id\Tests\Support\WebhookSignatureFixture;
use Cbox\Id\Webhooks\Exceptions\InvalidWebhookSignature;
use Cbox\Id\Webhooks\Support\CboxWebhookSignature;

/**
 * The receiver half of the Cbox scheme, held to the same cross-SDK fixture every SDK
 * verifies against — so the PHP verifier and the four SDK verifiers accept exactly the
 * same bytes and refuse the same flipped concatenation.
 */
function expectCboxWebhookFailure(callable $verify, string $reason): void
{
    try {
        $verify();
    } catch (InvalidWebhookSignature $e) {
        expect($e->reason)->toBe($reason);

        return;
    }

    test()->fail("Expected verification to fail with [{$reason}], but it passed.");
}

it('produces the fixture header for every case', function (array $case): void {
    expect(CboxWebhookSignature::headers($case['timestamp'], $case['body'], $case['secret']))->toBe([
        'X-Cbox-Timestamp' => (string) $case['timestamp'],
        'X-Cbox-Signature' => $case['header'],
    ]);
})->with(WebhookSignatureFixture::dataset());

it('verifies every fixture case', function (array $case): void {
    CboxWebhookSignature::verify($case['body'], ['X-Cbox-Signature' => $case['header']], $case['secret'], now: $case['timestamp']);

    expect(true)->toBeTrue();
})->with(WebhookSignatureFixture::dataset());

it('rejects every reversed-order signature', function (array $case): void {
    expectCboxWebhookFailure(
        fn () => CboxWebhookSignature::verify($case['body'], ['x-cbox-signature' => $case['reversed_order_header']], $case['secret'], now: $case['timestamp']),
        'signature_mismatch',
    );
})->with(WebhookSignatureFixture::dataset());

it('holds the signed timestamp to the tolerance in both directions', function (): void {
    $case = WebhookSignatureFixture::dataset()['envelope'][0];
    $headers = ['X-Cbox-Signature' => $case['header']];

    CboxWebhookSignature::verify($case['body'], $headers, $case['secret'], 60, $case['timestamp'] + 60);

    expectCboxWebhookFailure(fn () => CboxWebhookSignature::verify($case['body'], $headers, $case['secret'], 60, $case['timestamp'] + 61), 'timestamp_too_old');
    expectCboxWebhookFailure(fn () => CboxWebhookSignature::verify($case['body'], $headers, $case['secret'], 60, $case['timestamp'] - 61), 'timestamp_too_new');
});

it('fails a tampered body or timestamp', function (): void {
    $case = WebhookSignatureFixture::dataset()['envelope'][0];

    expectCboxWebhookFailure(
        fn () => CboxWebhookSignature::verify($case['body'].' ', ['X-Cbox-Signature' => $case['header']], $case['secret'], now: $case['timestamp']),
        'signature_mismatch',
    );

    $moved = str_replace('t='.$case['timestamp'], 't='.($case['timestamp'] + 1), $case['header']);

    expectCboxWebhookFailure(
        fn () => CboxWebhookSignature::verify($case['body'], ['X-Cbox-Signature' => $moved], $case['secret'], now: $case['timestamp']),
        'signature_mismatch',
    );
});

it('accepts any matching v1 among several', function (): void {
    $case = WebhookSignatureFixture::dataset()['envelope'][0];
    $header = 't='.$case['timestamp'].',v1='.$case['reversed_order_signature'].',v1='.$case['signature'].',v0=ignored';

    CboxWebhookSignature::verify($case['body'], ['X-Cbox-Signature' => [$header]], $case['secret'], now: $case['timestamp']);

    expect(true)->toBeTrue();
});

it('refuses missing or malformed signature headers with a stable reason', function (array $headers, string $reason): void {
    $case = WebhookSignatureFixture::dataset()['envelope'][0];

    expectCboxWebhookFailure(
        fn () => CboxWebhookSignature::verify($case['body'], $headers, $case['secret'], now: $case['timestamp']),
        $reason,
    );
})->with([
    'no header' => [['X-Cbox-Timestamp' => '1700000000'], 'missing_header'],
    'no timestamp' => [['X-Cbox-Signature' => 'v1=abc'], 'malformed_signature'],
    'two timestamps' => [['X-Cbox-Signature' => 't=1700000000,t=1700000001,v1=abc'], 'malformed_signature'],
    'not key=value' => [['X-Cbox-Signature' => 'garbage'], 'malformed_signature'],
    'no v1' => [['X-Cbox-Signature' => 't=1700000000,v0=abc'], 'unsupported_version'],
    'bad timestamp' => [['X-Cbox-Signature' => 't=17e8,v1=abc'], 'invalid_timestamp'],
]);

it('refuses an empty secret', function (): void {
    expectCboxWebhookFailure(fn () => CboxWebhookSignature::verify('{}', ['X-Cbox-Signature' => 't=1,v1=a'], ''), 'invalid_secret');
});
