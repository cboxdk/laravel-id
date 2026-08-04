<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/**
 * The WebAuthn Relying Party a ceremony runs under: the RP id credentials are scoped to,
 * and the exact origin the browser will report in `clientDataJSON`.
 *
 * The two travel together because they are only ever correct together — WebAuthn requires
 * the RP id to be the origin's effective domain or a registrable suffix of it, so a pair
 * assembled from two independently-read config keys can be individually plausible and
 * jointly impossible.
 */
readonly class RelyingParty
{
    public function __construct(
        /** The RP id — a bare registrable domain: no scheme, no port. */
        public string $id,
        /** The full origin, exactly as the browser reports it (scheme + host + port). */
        public string $origin,
    ) {}

    /** The origin's host, for comparing one party's reach against another's. */
    public function host(): string
    {
        $host = parse_url($this->origin, PHP_URL_HOST);

        return is_string($host) ? $host : '';
    }
}
