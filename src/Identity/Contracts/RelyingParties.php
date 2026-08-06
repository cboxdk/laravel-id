<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Contracts;

use Cbox\Id\Identity\ValueObjects\RelyingParty;

/**
 * Which WebAuthn Relying Party this request's passkey ceremony belongs to.
 *
 * Resolved per call, never captured, for the same reason the issuer is: a deployment
 * serving more than one host serves more than one RP, and a single pair read once from
 * static config can satisfy at most one of them. Everything a passkey ceremony asserts
 * — the `rp.id` handed to `navigator.credentials`, the RP-id hash in the authenticator
 * data, the origin in the client data — has to come from here, or the halves disagree
 * and the browser is rejected for answering exactly what it was asked.
 */
interface RelyingParties
{
    public function current(): RelyingParty;
}
