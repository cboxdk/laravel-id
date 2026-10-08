<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Exceptions;

use Cbox\Id\Webhooks\Support\CboxWebhookSignature;
use Cbox\Id\Webhooks\Support\StandardWebhookSignature;
use RuntimeException;

/**
 * A received webhook did not verify — thrown by the receiver-side helpers
 * {@see StandardWebhookSignature::verify()} and {@see CboxWebhookSignature::verify()}.
 *
 * `$reason` is a stable, machine-readable code a receiver can log, count or branch on;
 * the message is for the developer. Whatever the reason, the only correct response is to
 * refuse the request without acting on its body — the reasons exist so a misconfigured
 * receiver (a wrong secret, a clock that drifted, a proxy that rewrote the body) can be
 * told apart from an attack in the receiver's own logs, not so some of them can be let
 * through. Respond with a 4xx: the sender retries, and a retry of a genuine delivery
 * carries a fresh timestamp and the same id.
 *
 * - `missing_header` — a header the scheme requires is absent or empty.
 * - `invalid_timestamp` — the timestamp is not a positive integer of unix seconds.
 * - `timestamp_too_old` / `timestamp_too_new` — outside the tolerance window, in either
 *   direction (a future timestamp is as much a replay vector as a stale one).
 * - `invalid_secret` — the verifying secret is unusable: a Standard Webhooks secret
 *   without its `whsec_` prefix, not base64, or empty.
 * - `malformed_signature` — the signature header cannot be parsed at all.
 * - `unsupported_version` — the header parsed, but carries no signature of a version
 *   this helper verifies (`v1`).
 * - `signature_mismatch` — a `v1` signature was present and none of them matched: a wrong
 *   secret, or a body, id or timestamp that changed after signing.
 */
class InvalidWebhookSignature extends RuntimeException
{
    public function __construct(public readonly string $reason, string $message)
    {
        parent::__construct($message);
    }

    public static function missingHeader(string $header): self
    {
        return new self('missing_header', "The webhook is missing its [{$header}] header.");
    }

    public static function invalidTimestamp(): self
    {
        return new self('invalid_timestamp', 'The webhook timestamp is not a positive integer of unix seconds.');
    }

    public static function timestampTooOld(int $tolerance): self
    {
        return new self('timestamp_too_old', "The webhook timestamp is more than {$tolerance} seconds in the past.");
    }

    public static function timestampTooNew(int $tolerance): self
    {
        return new self('timestamp_too_new', "The webhook timestamp is more than {$tolerance} seconds in the future.");
    }

    public static function invalidSecret(string $detail): self
    {
        return new self('invalid_secret', "The webhook secret cannot be used: {$detail}");
    }

    public static function malformedSignature(): self
    {
        return new self('malformed_signature', 'The webhook signature header could not be parsed.');
    }

    public static function unsupportedVersion(): self
    {
        return new self('unsupported_version', 'The webhook signature header carries no v1 signature.');
    }

    public static function mismatch(): self
    {
        return new self('signature_mismatch', 'No webhook signature matched the payload.');
    }
}
