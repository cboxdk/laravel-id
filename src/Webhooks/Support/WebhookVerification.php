<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Support;

use Cbox\Id\Webhooks\Exceptions\InvalidWebhookSignature;

/**
 * The two receiver-side steps both signature schemes share: reading a header out of
 * whatever shape the receiver's framework hands over, and holding a signed timestamp to a
 * tolerance window.
 *
 * @internal Used by {@see StandardWebhookSignature} and {@see CboxWebhookSignature}; not a
 *           public API of its own.
 */
class WebhookVerification
{
    /**
     * One header's value, matched case-insensitively (RFC 9110 §5.1 — field names are
     * case-insensitive, and frameworks disagree on what case they hand over). A value may
     * be a string or a list of strings — the shape `$request->headers->all()` returns in
     * Laravel and Symfony — in which case the first is used.
     *
     * @param  array<array-key, mixed>  $headers
     */
    public static function header(array $headers, string $name): string
    {
        foreach ($headers as $key => $value) {
            if (! is_string($key) || strcasecmp($key, $name) !== 0) {
                continue;
            }

            if (is_array($value)) {
                $value = array_values($value)[0] ?? null;
            }

            if (is_string($value) && trim($value) !== '') {
                return trim($value);
            }
        }

        throw InvalidWebhookSignature::missingHeader($name);
    }

    /**
     * Parse a signed timestamp and hold it to `$tolerance` seconds of `$now` in BOTH
     * directions. A timestamp far in the future is as much a replay vector as a stale one:
     * a captured delivery stamped ahead of time would stay acceptable for as long as the
     * stamp is ahead.
     *
     * Strict about shape — unix seconds, digits only, no sign, no fraction — because the
     * timestamp is part of the signed string: a lenient parse (`intval('1614265330.0')`)
     * would accept a header whose bytes differ from what was signed and then fail the MAC
     * with a misleading reason.
     */
    public static function timestamp(string $value, int $tolerance, ?int $now = null): int
    {
        if (preg_match('/^[1-9][0-9]{0,17}$/', $value) !== 1) {
            throw InvalidWebhookSignature::invalidTimestamp();
        }

        $timestamp = (int) $value;
        $now ??= time();
        $tolerance = max(0, $tolerance);

        if ($timestamp < $now - $tolerance) {
            throw InvalidWebhookSignature::timestampTooOld($tolerance);
        }

        if ($timestamp > $now + $tolerance) {
            throw InvalidWebhookSignature::timestampTooNew($tolerance);
        }

        return $timestamp;
    }
}
