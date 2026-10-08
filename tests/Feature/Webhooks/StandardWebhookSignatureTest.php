<?php

declare(strict_types=1);

use Cbox\Id\Tests\Support\StandardWebhooksFixture;
use Cbox\Id\Webhooks\Exceptions\InvalidWebhookSignature;
use Cbox\Id\Webhooks\Support\StandardWebhookSignature;

/**
 * The Standard Webhooks helper, held to the specification's published vectors.
 *
 * The fixture's first case is copied from the spec repository's own library tests, so a
 * pass here means "agrees with the spec authors", not "agrees with itself". Nothing below
 * builds the signed string locally: the concatenation order comes from the fixture.
 */

/** Headers for a fixture case, signed at the case's own timestamp. */
function standardWebhookHeaders(array $case, ?string $signature = null): array
{
    return [
        'webhook-id' => $case['id'],
        'webhook-timestamp' => (string) $case['timestamp'],
        'webhook-signature' => $signature ?? $case['header'],
    ];
}

function expectStandardWebhookFailure(callable $verify, string $reason): void
{
    try {
        $verify();
    } catch (InvalidWebhookSignature $e) {
        expect($e->reason)->toBe($reason);

        return;
    }

    test()->fail("Expected verification to fail with [{$reason}], but it passed.");
}

it('is an honest HMAC vector for every fixture case', function (array $case): void {
    $document = StandardWebhooksFixture::document();

    $signed = strtr($document['signed_payload_template'], [
        '{id}' => $case['id'],
        '{timestamp}' => (string) $case['timestamp'],
        '{body}' => $case['body'],
    ]);
    $key = base64_decode(substr($case['secret'], strlen('whsec_')), true);

    expect(base64_encode(hash_hmac('sha256', $signed, (string) $key, true)))->toBe($case['signature'])
        ->and(strtr($document['signature_entry_template'], ['{signature}' => $case['signature']]))->toBe($case['header']);
})->with(StandardWebhooksFixture::dataset());

it('pins the spec wire format, stated once and not read from the file it guards', function (): void {
    $document = StandardWebhooksFixture::document();

    expect($document['signed_payload_template'])->toBe('{id}.{timestamp}.{body}')
        ->and($document['signature_entry_template'])->toBe('v1,{signature}')
        // The spec's own number: if this case is ever "regenerated", it is no longer the spec's.
        ->and($document['cases'][0]['name'])->toBe('reference_library_sign')
        ->and($document['cases'][0]['header'])->toBe('v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=');
});

it('signs every fixture case exactly as the spec vector says', function (array $case): void {
    expect(StandardWebhookSignature::sign($case['id'], $case['timestamp'], $case['body'], $case['secret']))
        ->toBe($case['header'])
        ->and(StandardWebhookSignature::headers($case['id'], $case['timestamp'], $case['body'], $case['secret']))
        ->toBe(standardWebhookHeaders($case));
})->with(StandardWebhooksFixture::dataset());

it('verifies every fixture case', function (array $case): void {
    StandardWebhookSignature::verify($case['body'], standardWebhookHeaders($case), $case['secret'], now: $case['timestamp']);

    expect(true)->toBeTrue();
})->with(StandardWebhooksFixture::dataset());

it('rejects the same input signed in the wrong order', function (array $case): void {
    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify($case['body'], standardWebhookHeaders($case, 'v1,'.$case['reordered_signature']), $case['secret'], now: $case['timestamp']),
        'signature_mismatch',
    );
})->with(StandardWebhooksFixture::dataset());

it('converts a Cbox-scheme hex secret to whsec losslessly', function (): void {
    $case = StandardWebhooksFixture::dataset()['cbox_hex_secret_as_whsec'][0];

    expect(StandardWebhookSignature::secretFor($case['cbox_secret']))->toBe($case['secret'])
        // A whsec secret is already in the right form.
        ->and(StandardWebhookSignature::secretFor($case['secret']))->toBe($case['secret'])
        // And the decoded key IS the key the Cbox scheme signs with.
        ->and(base64_decode(substr($case['secret'], 6), true))->toBe($case['cbox_secret']);
});

it('mints whsec secrets of 32 random bytes', function (): void {
    $secret = StandardWebhookSignature::mintSecret();

    expect($secret)->toStartWith('whsec_')
        ->and(strlen((string) base64_decode(substr($secret, 6), true)))->toBe(32)
        ->and(StandardWebhookSignature::mintSecret())->not->toBe($secret);
});

it('accepts headers in any case and in the list shape a framework hands over', function (): void {
    $case = StandardWebhooksFixture::dataset()['reference_library_sign'][0];

    StandardWebhookSignature::verify($case['body'], [
        'Webhook-Id' => [$case['id']],
        'WEBHOOK-TIMESTAMP' => [(string) $case['timestamp']],
        'webhook-signature' => [$case['header']],
    ], $case['secret'], now: $case['timestamp']);

    expect(true)->toBeTrue();
});

it('accepts a header carrying several signatures when one matches, skipping other versions', function (): void {
    // The shape of the reference libraries' multi-signature test: junk v1 entries, an
    // unknown version, and the real one somewhere in the middle.
    $case = StandardWebhooksFixture::dataset()['reference_library_sign'][0];
    $header = implode(' ', [
        'v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=',
        'v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=',
        $case['header'],
        'v1a,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=',
    ]);

    StandardWebhookSignature::verify($case['body'], standardWebhookHeaders($case, $header), $case['secret'], now: $case['timestamp']);

    expect(true)->toBeTrue();
});

it('emits one v1 signature per secret, each verifiable on its own (rotation)', function (): void {
    $case = StandardWebhooksFixture::dataset()['reference_library_sign'][0];
    $next = StandardWebhookSignature::mintSecret();

    $header = StandardWebhookSignature::sign($case['id'], $case['timestamp'], $case['body'], $case['secret'], $next);

    expect(explode(' ', $header))->toHaveCount(2)
        ->and(explode(' ', $header)[0])->toBe($case['header']);

    // A receiver still on the old secret and one already on the new both verify.
    foreach ([$case['secret'], $next] as $secret) {
        StandardWebhookSignature::verify($case['body'], standardWebhookHeaders($case, $header), $secret, now: $case['timestamp']);
    }

    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify($case['body'], standardWebhookHeaders($case, $header), StandardWebhookSignature::mintSecret(), now: $case['timestamp']),
        'signature_mismatch',
    );
});

it('holds the timestamp to the tolerance in both directions', function (): void {
    $case = StandardWebhooksFixture::dataset()['reference_library_sign'][0];
    $headers = standardWebhookHeaders($case);
    $ts = $case['timestamp'];

    // Exactly at the edges is accepted…
    StandardWebhookSignature::verify($case['body'], $headers, $case['secret'], 300, $ts + 300);
    StandardWebhookSignature::verify($case['body'], $headers, $case['secret'], 300, $ts - 300);

    // …one second past either edge is not.
    expectStandardWebhookFailure(fn () => StandardWebhookSignature::verify($case['body'], $headers, $case['secret'], 300, $ts + 301), 'timestamp_too_old');
    expectStandardWebhookFailure(fn () => StandardWebhookSignature::verify($case['body'], $headers, $case['secret'], 300, $ts - 301), 'timestamp_too_new');
});

it('fails a tampered body, id or timestamp', function (): void {
    $case = StandardWebhooksFixture::dataset()['reference_library_sign'][0];

    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify('{"test": 2432232315}', standardWebhookHeaders($case), $case['secret'], now: $case['timestamp']),
        'signature_mismatch',
    );

    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify($case['body'], ['webhook-id' => 'msg_other'] + standardWebhookHeaders($case), $case['secret'], now: $case['timestamp']),
        'signature_mismatch',
    );

    // A timestamp moved forward by one second — still well inside the window, so it is
    // the MAC, not the tolerance, that refuses it.
    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify($case['body'], ['webhook-timestamp' => (string) ($case['timestamp'] + 1)] + standardWebhookHeaders($case), $case['secret'], now: $case['timestamp']),
        'signature_mismatch',
    );
});

it('refuses each missing header', function (string $header): void {
    $case = StandardWebhooksFixture::dataset()['reference_library_sign'][0];
    $headers = standardWebhookHeaders($case);
    unset($headers[$header]);

    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify($case['body'], $headers, $case['secret'], now: $case['timestamp']),
        'missing_header',
    );
})->with(['webhook-id', 'webhook-timestamp', 'webhook-signature']);

it('refuses a timestamp that is not unix seconds', function (string $timestamp): void {
    $case = StandardWebhooksFixture::dataset()['reference_library_sign'][0];

    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify($case['body'], ['webhook-timestamp' => $timestamp] + standardWebhookHeaders($case), $case['secret'], now: $case['timestamp']),
        'invalid_timestamp',
    );
})->with(['float' => '1614265330.0', 'negative' => '-1614265330', 'words' => 'yesterday', 'leading zero' => '01614265330', 'overflowing' => '16142653300000000000']);

it('refuses a secret without the whsec_ prefix, or one that is not base64', function (string $secret): void {
    $case = StandardWebhooksFixture::dataset()['reference_library_sign'][0];

    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify($case['body'], standardWebhookHeaders($case), $secret, now: $case['timestamp']),
        'invalid_secret',
    );
})->with([
    // Bare base64 — accepted by the reference libraries, refused here so a pasted hex
    // secret (which is also valid base64) cannot silently key the HMAC with the wrong bytes.
    'unprefixed' => 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
    'empty after prefix' => 'whsec_',
    'not base64' => 'whsec_not*base64!',
]);

it('refuses a signature header with no v1 entry, or nothing parseable', function (): void {
    $case = StandardWebhooksFixture::dataset()['reference_library_sign'][0];

    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify($case['body'], standardWebhookHeaders($case, 'v1a,'.$case['signature'].' v2,abc'), $case['secret'], now: $case['timestamp']),
        'unsupported_version',
    );

    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify($case['body'], standardWebhookHeaders($case, $case['signature']), $case['secret'], now: $case['timestamp']),
        'malformed_signature',
    );

    // The reference libraries' "v1," with nothing after the comma.
    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify($case['body'], standardWebhookHeaders($case, 'v1,'), $case['secret'], now: $case['timestamp']),
        'malformed_signature',
    );

    // The reference libraries' "invalid signature" case.
    expectStandardWebhookFailure(
        fn () => StandardWebhookSignature::verify($case['body'], standardWebhookHeaders($case, 'v1,dawfeoifkpqwoekfpqoekf'), $case['secret'], now: $case['timestamp']),
        'signature_mismatch',
    );
});
