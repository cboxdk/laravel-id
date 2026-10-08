<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Enums;

/**
 * How an endpoint's deliveries are signed. Chosen per endpoint, and changeable later.
 *
 * - {@see self::Cbox} — the original scheme and the default: `X-Cbox-Timestamp` plus
 *   `X-Cbox-Signature: t=<ts>,v1=<hex HMAC-SHA256 of "<ts>.<body>">`, keyed by the
 *   revealed secret string exactly as shown. Every endpoint that existed before the
 *   scheme was selectable is on it, and its wire format is unchanged byte for byte.
 * - {@see self::StandardWebhooks} — the Standard Webhooks specification
 *   (https://www.standardwebhooks.com/): `webhook-id`, `webhook-timestamp` and
 *   `webhook-signature: v1,<base64 HMAC-SHA256 of "<id>.<ts>.<body>">`, keyed by the
 *   base64-decoded bytes of a `whsec_` secret — so any Standard Webhooks library, in any
 *   language, verifies the delivery without code written against this package.
 *
 * A new enum rather than a flag on an existing one: a host may `match` on the enums it
 * already has, and a new case there would break it.
 */
enum SignatureScheme: string
{
    case Cbox = 'cbox';
    case StandardWebhooks = 'standard_webhooks';
}
