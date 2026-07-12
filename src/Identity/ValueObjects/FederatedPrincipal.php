<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\ValueObjects;

/**
 * An identity asserted by an external provider (SSO/social), to be provisioned
 * into a local user + identity link.
 *
 * Note: the platform never merges an incoming identity into a pre-existing
 * account by matching email — that would let a provider hijack another user's
 * account. A first-seen identity whose email already belongs to an account is
 * refused; linking is an explicit, authenticated action (see Subjects::link()).
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
