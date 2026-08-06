<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\ValueObjects;

/**
 * Everything needed to fire one hook request, assembled BEFORE any network call.
 *
 * Preparation is what can fail locally — the SSRF guard rejecting a target, opening
 * the sealed signing secret, encoding the body — and it must fail per endpoint, not
 * take the whole pooled fan-out down with it. Splitting it out lets a failed
 * preparation become that one endpoint's fail-closed deny while its siblings still fly.
 */
final readonly class PreparedActionRequest
{
    /**
     * @param  array<string, string>  $headers
     * @param  array<string, mixed>  $options  pinned resolution options from the SSRF guard
     */
    public function __construct(
        public string $endpointId,
        public string $url,
        public string $body,
        public array $headers,
        public array $options,
    ) {}
}
