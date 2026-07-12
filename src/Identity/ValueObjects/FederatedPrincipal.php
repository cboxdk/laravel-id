<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/**
 * An identity asserted by an external provider (SSO/social), to be provisioned
 * into a local user + identity link.
 */
final readonly class FederatedPrincipal
{
    /**
     * @param  array<string, mixed>  $raw
     */
    public function __construct(
        public string $provider,
        public string $subject,
        public ?string $email = null,
        public ?string $name = null,
        public ?string $connectionId = null,
        public array $raw = [],
    ) {}
}
