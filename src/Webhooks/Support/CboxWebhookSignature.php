<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Support;

use Cbox\Id\Webhooks\Enums\SignatureScheme;
use Cbox\Id\Webhooks\Exceptions\InvalidWebhookSignature;

/**
 * The Cbox webhook signature — {@see SignatureScheme::Cbox}, the default — both halves:
 * the sender's {@see headers()} and the receiver's {@see verify()}.
 *
 * The wire format is pinned by the cross-SDK fixture `tests/Fixtures/Webhooks/signature.json`
 * and is unchanged from every release before this class existed:
 *
 *     X-Cbox-Timestamp: <ts>
 *     X-Cbox-Signature: t=<ts>,v1=<lowercase hex HMAC-SHA256 of "<ts>.<raw body>">
 *
 * keyed by the endpoint's secret string exactly as revealed (no decoding — a `whsec_`
 * secret used under this scheme keys the HMAC with its literal characters).
 *
 * Until now the package shipped only the sending half, and every receiver re-implemented
 * the verification. {@see verify()} is that half, written once: constant-time comparison,
 * a tolerance window in both directions, and the same typed failures as
 * {@see StandardWebhookSignature::verify()}.
 */
class CboxWebhookSignature
{
    public const string TIMESTAMP_HEADER = 'X-Cbox-Timestamp';

    public const string SIGNATURE_HEADER = 'X-Cbox-Signature';

    public const int DEFAULT_TOLERANCE = 300;

    /** Lowercase hex HMAC-SHA256 of `"{timestamp}.{payload}"`. */
    public static function sign(int $timestamp, string $payload, string $secret): string
    {
        return hash_hmac('sha256', $timestamp.'.'.$payload, $secret);
    }

    /**
     * The two headers a delivery carries, ready for the HTTP client.
     *
     * @return array{X-Cbox-Timestamp: string, X-Cbox-Signature: string}
     */
    public static function headers(int $timestamp, string $payload, string $secret): array
    {
        return [
            self::TIMESTAMP_HEADER => (string) $timestamp,
            self::SIGNATURE_HEADER => 't='.$timestamp.',v1='.self::sign($timestamp, $payload, $secret),
        ];
    }

    /**
     * Verify a received delivery, or throw.
     *
     * `$payload` must be the RAW request body. The timestamp that counts is the `t=` inside
     * `X-Cbox-Signature` — it is the one the MAC covers; `X-Cbox-Timestamp` is a
     * convenience copy and is not consulted. More than one `v1=` entry is accepted (any
     * may match), so a receiver is already correct if a sender ever signs with two
     * secrets; unknown keys are ignored.
     *
     * @param  array<array-key, mixed>  $headers
     *
     * @throws InvalidWebhookSignature with a stable `$reason`.
     */
    public static function verify(string $payload, array $headers, string $secret, int $tolerance = self::DEFAULT_TOLERANCE, ?int $now = null): void
    {
        if ($secret === '') {
            throw InvalidWebhookSignature::invalidSecret('the secret is empty.');
        }

        $header = WebhookVerification::header($headers, self::SIGNATURE_HEADER);

        $timestampValue = null;
        $candidates = [];

        foreach (explode(',', $header) as $pair) {
            $parts = explode('=', trim($pair), 2);

            if (count($parts) !== 2) {
                throw InvalidWebhookSignature::malformedSignature();
            }

            [$name, $value] = $parts;

            if ($name === 't') {
                // Exactly one: two timestamps would leave it ambiguous which one was signed.
                if ($timestampValue !== null) {
                    throw InvalidWebhookSignature::malformedSignature();
                }

                $timestampValue = $value;
            } elseif ($name === 'v1' && $value !== '') {
                $candidates[] = $value;
            }
        }

        if ($timestampValue === null) {
            throw InvalidWebhookSignature::malformedSignature();
        }

        $timestamp = WebhookVerification::timestamp($timestampValue, $tolerance, $now);

        if ($candidates === []) {
            throw InvalidWebhookSignature::unsupportedVersion();
        }

        $expected = self::sign($timestamp, $payload, $secret);

        foreach ($candidates as $candidate) {
            if (hash_equals($expected, $candidate)) {
                return;
            }
        }

        throw InvalidWebhookSignature::mismatch();
    }
}
