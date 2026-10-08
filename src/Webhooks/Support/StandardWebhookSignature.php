<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Support;

use Cbox\Id\Webhooks\Enums\SignatureScheme;
use Cbox\Id\Webhooks\Exceptions\InvalidWebhookSignature;

/**
 * The Standard Webhooks signature (https://www.standardwebhooks.com/, spec
 * `standard-webhooks.md`, "Signature scheme") — both halves: the sender's
 * {@see headers()} / {@see sign()} that {@see SignatureScheme::StandardWebhooks} endpoints
 * are delivered with, and the receiver's {@see verify()}.
 *
 * The wire format, from the spec:
 *
 * - `webhook-id` — the message id. Here it is the delivery id, which is the same on every
 *   retry of one delivery, so a receiver can use it as the idempotency key the spec says
 *   it is.
 * - `webhook-timestamp` — integer unix seconds of THIS attempt (a retry is re-signed with
 *   a fresh one, so it passes a receiver's tolerance window).
 * - `webhook-signature` — a SPACE-delimited list of `<version>,<signature>`. `v1` is
 *   HMAC-SHA256 over `"{id}.{timestamp}.{body}"`, base64 (standard alphabet, padded). A
 *   list, so a sender rotating its secret can sign with both and a receiver holding either
 *   one verifies; a receiver skips versions it does not know (`v1a` is the asymmetric
 *   ed25519 scheme, which this package does not send).
 *
 * The secret is `whsec_` followed by base64 of 24–64 random bytes, and — the detail that
 * trips hand-written verifiers — the HMAC key is the base64-DECODED bytes, not the string.
 * {@see mintSecret()} mints 32 bytes.
 *
 * Only PHP primitives: `hash_hmac`, `hash_equals`, `random_bytes`, base64. Nothing here
 * is a cryptographic construction of its own; it is the spec's byte layout around them.
 *
 * Verified against the specification's own published vectors (the `sign` test of the
 * reference libraries), in tests/Fixtures/Webhooks/standard-webhooks.json.
 */
class StandardWebhookSignature
{
    public const string SECRET_PREFIX = 'whsec_';

    public const string ID_HEADER = 'webhook-id';

    public const string TIMESTAMP_HEADER = 'webhook-timestamp';

    public const string SIGNATURE_HEADER = 'webhook-signature';

    /** Five minutes, the tolerance the reference libraries use. */
    public const int DEFAULT_TOLERANCE = 300;

    /** Random bytes in a minted secret: 256 bits, inside the spec's 24–64 byte range. */
    private const int SECRET_BYTES = 32;

    /**
     * A fresh `whsec_` secret — what a Standard Webhooks endpoint is registered with and
     * what its owner pastes into their receiver.
     */
    public static function mintSecret(): string
    {
        return self::SECRET_PREFIX.base64_encode(random_bytes(self::SECRET_BYTES));
    }

    /**
     * The `whsec_` form of an endpoint's secret, whichever scheme it was minted under.
     *
     * A secret minted for a Standard Webhooks endpoint already is one and is returned as
     * is. A secret minted for a Cbox-scheme endpoint is 64 hex characters, and the Cbox
     * scheme keys its HMAC with those 64 characters as bytes; `whsec_` + base64 of the
     * SAME 64 bytes is a valid Standard Webhooks secret (64 bytes is the top of the spec's
     * range) whose decoded key is exactly that key. The representation is lossless, so an
     * existing endpoint can be moved to Standard Webhooks without minting a new secret:
     * its owner converts the secret they already hold —
     * `'whsec_'.base64_encode($secret)` — and nothing secret has to be shown again.
     */
    public static function secretFor(string $endpointSecret): string
    {
        return str_starts_with($endpointSecret, self::SECRET_PREFIX)
            ? $endpointSecret
            : self::SECRET_PREFIX.base64_encode($endpointSecret);
    }

    /**
     * The `webhook-signature` value for one message: one `v1,` entry per secret, space
     * delimited. Pass more than one secret only while rotating — each receiver verifies
     * against the one it holds.
     *
     * @throws InvalidWebhookSignature `invalid_secret` when a secret is not a usable
     *                                 `whsec_` secret.
     */
    public static function sign(string $id, int $timestamp, string $payload, string $secret, string ...$moreSecrets): string
    {
        $signatures = [];

        foreach ([$secret, ...$moreSecrets] as $each) {
            $signatures[] = 'v1,'.self::mac($id, $timestamp, $payload, self::key($each));
        }

        return implode(' ', $signatures);
    }

    /**
     * The three headers a delivery carries, ready for the HTTP client.
     *
     * @return array{webhook-id: string, webhook-timestamp: string, webhook-signature: string}
     */
    public static function headers(string $id, int $timestamp, string $payload, string $secret, string ...$moreSecrets): array
    {
        return [
            self::ID_HEADER => $id,
            self::TIMESTAMP_HEADER => (string) $timestamp,
            self::SIGNATURE_HEADER => self::sign($id, $timestamp, $payload, $secret, ...$moreSecrets),
        ];
    }

    /**
     * Verify a received delivery, or throw.
     *
     * `$payload` must be the RAW request body, byte for byte — not a re-encoding of the
     * parsed JSON, which differs in whitespace, escaping and key order and so fails the
     * MAC. `$headers` may be a plain map or `$request->headers->all()`; names are matched
     * case-insensitively. `$secret` is the endpoint's `whsec_` secret.
     *
     * Checks, in order: the secret is usable; all three headers are present; the timestamp
     * is unix seconds within `$tolerance` of `$now` in either direction; the signature
     * header carries at least one `v1` entry; and one of those entries matches, compared
     * in constant time. Entries of other versions are skipped, as the spec requires.
     *
     * After this returns, use `webhook-id` as the idempotency key: delivery is
     * at-least-once, and a retry of the same message carries the same id.
     *
     * @param  array<array-key, mixed>  $headers
     *
     * @throws InvalidWebhookSignature with a stable `$reason`.
     */
    public static function verify(string $payload, array $headers, string $secret, int $tolerance = self::DEFAULT_TOLERANCE, ?int $now = null): void
    {
        $key = self::key($secret);

        $id = WebhookVerification::header($headers, self::ID_HEADER);
        $timestampHeader = WebhookVerification::header($headers, self::TIMESTAMP_HEADER);
        $signatureHeader = WebhookVerification::header($headers, self::SIGNATURE_HEADER);

        $timestamp = WebhookVerification::timestamp($timestampHeader, $tolerance, $now);

        $candidates = [];
        $parsed = 0;

        foreach (preg_split('/\s+/', $signatureHeader, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $entry) {
            $parts = explode(',', $entry, 2);

            if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
                continue;
            }

            $parsed++;

            if ($parts[0] === 'v1') {
                $candidates[] = $parts[1];
            }
        }

        if ($parsed === 0) {
            throw InvalidWebhookSignature::malformedSignature();
        }

        if ($candidates === []) {
            throw InvalidWebhookSignature::unsupportedVersion();
        }

        $expected = self::mac($id, $timestamp, $payload, $key);

        foreach ($candidates as $candidate) {
            if (hash_equals($expected, $candidate)) {
                return;
            }
        }

        throw InvalidWebhookSignature::mismatch();
    }

    /** base64(HMAC-SHA256(key, "{id}.{timestamp}.{payload}")). */
    private static function mac(string $id, int $timestamp, string $payload, string $key): string
    {
        return base64_encode(hash_hmac('sha256', $id.'.'.$timestamp.'.'.$payload, $key, true));
    }

    /**
     * The HMAC key inside a `whsec_` secret: the base64-decoded bytes after the prefix.
     *
     * The prefix is REQUIRED here, where the reference libraries also accept bare base64.
     * A Cbox-scheme secret is 64 hex characters, and hex is valid base64 — so a receiver
     * that pasted the hex secret straight in would be silently keyed with the wrong bytes
     * and see every delivery fail as a mismatch. Refusing the unprefixed form turns that
     * into an `invalid_secret` that names the problem; {@see secretFor()} converts.
     */
    private static function key(string $secret): string
    {
        if (! str_starts_with($secret, self::SECRET_PREFIX)) {
            throw InvalidWebhookSignature::invalidSecret('a Standard Webhooks secret starts with "whsec_" (convert a hex secret with StandardWebhookSignature::secretFor()).');
        }

        $key = base64_decode(substr($secret, strlen(self::SECRET_PREFIX)), true);

        if ($key === false || $key === '') {
            throw InvalidWebhookSignature::invalidSecret('the part after "whsec_" must be non-empty base64.');
        }

        return $key;
    }
}
